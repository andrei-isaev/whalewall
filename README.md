# whalewall

Automate management of firewall rules for Docker containers.

## Requirements

This fork intentionally supports a narrow deployment profile:

- Linux with a recent kernel (5.13 or newer is recommended for Landlock support)
- `linux/amd64` for the reviewed binary and container build path
- rootful Docker Engine using the `iptables` firewall backend
- the nftables-backed iptables implementation (`iptables-nft`), not `iptables-legacy`
- IPv4 Docker networks only
- bridge traffic passed through netfilter

Docker Engine 29's native `nftables` firewall backend is **not** supported. It does not create the
`ip filter DOCKER-USER` chain that whalewall currently integrates with. Rootless Docker, Docker
Swarm, macvlan networks, host-networked managed containers, and IPv6 are also unsupported.

Check the host before deploying:

```sh
docker info | grep 'Firewall Backend'
command -v iptables >/dev/null && sudo iptables --version || true
sudo nft list chain ip filter DOCKER-USER
cat /proc/sys/net/bridge/bridge-nf-call-iptables
```

The required results are `Firewall Backend: iptables`, an existing nftables `DOCKER-USER` chain, and
a bridge netfilter value of `1`. If the optional `iptables` CLI is installed, it should report
`(nf_tables)`, not `legacy`. The executable itself is not required by whalewall; whalewall programs
nftables through netlink rather than invoking it.

On hosts where bridge filtering is not already enabled, load and persist it before starting
whalewall:

```sh
sudo modprobe br_netfilter
printf '%s\n' br_netfilter | sudo tee /etc/modules-load.d/br_netfilter.conf
printf '%s\n' 'net.bridge.bridge-nf-call-iptables = 1' |
  sudo tee /etc/sysctl.d/99-docker-bridge-filter.conf
sudo sysctl --system
```

If `/etc/docker/daemon.json` is used, keep Docker on the supported backend by merging this setting
with the existing JSON (do not overwrite unrelated daemon settings):

```json
{
  "firewall-backend": "iptables"
}
```

Validate daemon configuration before a maintenance-window restart:

```sh
sudo dockerd --validate --config-file=/etc/docker/daemon.json
```

## Purpose

Docker by default creates iptables rules to handle container traffic that override almost all user-set
rules. There are two main ways to get around this:

1. Prevent Docker from creating any iptables rules by setting `"iptables": false` in `/etc/docker/daemon.json`
    - This is the nuclear approach. It will break most networking for containers, and require that
    you manage iptables for containers manually, which can be a very involved process.
2. Add rules to the `DOCKER-USER` iptables chain
    - Docker ensures that rules in this chain are processed *before* any rules Docker creates.

Adding rules to the `DOCKER-USER` chain is what whalewall does to avoid managing more firewall rules
than it needs to. You may be wondering if whalewall is necessary, after all it is very easy to add
firewall rules to the `DOCKER-USER` chain yourself. Well, Docker containers and networks are ephemeral,
meaning every time a container or network is destroyed and recreated, the IP address and subnet
respectively will be randomized. Whalewall takes care of creating or deleting rules when containers
are created or killed, which would be very tedious and error-prone manually. Finally, as well as
managing firewall rules to limit traffic to and from localhost and external interfaces, whalewall
can also enforce container network isolation by limiting traffic between containers.

## Mechanism

Whalewall listens for Docker container `start` and `die` events and creates or deletes
[nftables](https://wiki.nftables.org/wiki-nftables/index.php/What_is_nftables%3F)
rules appropriately. Why is nftables used instead of iptables? A few reasons:

- nftables can be configured programmatically unlike iptables, removing the need for whalewall to
execute any binaries
- nftables allows for first-class sets and maps in firewall rules which can greatly speed up
traffic matching in the kernel
- In most distros, iptables rules are translated to nftables rules under the hood, making iptables
rules compatible with nftables rules

Whalewall stores details of containers it is managing rules for in a SQLite database. If containers
are started or stopped while whalewall isn't running, whalewall will compare currently running
containers to what was last saved to the database and create/delete firewall rules appropriately.

## Security

Whalewall needs the `NET_ADMIN` capability to manage nftables rules. It also needs to be a member
of the `docker` group in order to use `/var/run/docker.sock` to receive events from the
local Docker daemon.

To reduce attack surface, [seccomp](https://docs.kernel.org/next/userspace-api/seccomp_filter.html)
restricts the process to its required syscalls; failure to install the filter is fatal. Filesystem
confinement with [Landlock](https://docs.kernel.org/userspace-api/landlock.html) is best-effort:
Linux first provides it in 5.13, and whalewall logs and continues when the kernel does not support
it. If Landlock is part of your threat model, require a supported kernel/configuration and verify
the `applied landlock rules` startup log. These controls still cannot prevent code executing in the
whalewall process from abusing its Docker socket, which can trivially lead to privilege escalation.

Mounting the Docker socket with `:ro` only makes the socket file mount read-only; it does not turn
the Docker API into a read-only API. Treat whalewall as a host-privileged service. A narrowly
configured Docker socket proxy reduces API exposure, but does not reduce the authority granted by
host `NET_ADMIN`.

Whalewall is an IPv4 layer-3/layer-4 policy manager, not a complete hostile-workload isolation
boundary for containers on the same layer-2 bridge. It identifies a container by its IPv4 address;
it does not bind that identity to a bridge port, MAC address, or cgroup, and the `ip` table does not
filter ARP or IPv6. Do not use overlapping IPv4 addresses or subnets across Docker networks on the
host: the dispatcher is address-keyed and cannot distinguish identical addresses on different
interfaces. Docker grants `NET_RAW` by default, which permits raw and packet sockets. Drop
`NET_RAW` from every managed workload that does not need it (prefer `cap_drop: [ALL]` followed by
only the capabilities the workload actually needs). This materially reduces IP/ARP spoofing risk,
but it does not turn a shared bridge into a strong security boundary.

Docker also starts and connects containers independently of whalewall. There is an unavoidable
window between a Docker lifecycle change and whalewall applying or reconciling its rules. Invalid
opt-in or policy labels are quarantined once processed, but a transient Docker, nftables, or database
failure must still be treated as a deployment failure. Start and verify whalewall before protected
services, watch its logs continuously, and test both allowed and forbidden traffic after every
policy or topology change.

Run exactly one whalewall instance per host. Multiple instances can race while replacing the same
chains, maps, and SQLite ownership state.

For a strict no-crosstalk boundary between potentially compromised workloads, use a separate
user-defined bridge for each permitted edge (for example, one Caddy-to-backend bridge per backend)
in addition to whalewall. Do not attach unrelated services to those bridges. Whalewall is useful
defence in depth and for controlling layer-3/layer-4 egress; it is not a replacement for that
topology.

## Installation

### Docker image

The `Publish image` GitHub Actions workflow publishes `linux/amd64` images to
`ghcr.io/andrei-isaev/whalewall`. Manual publication is restricted to `master`; version tags must
start with `v`. The workflow refuses to publish unless the exact source commit already passed the
Docker 29 `Test` workflow. It publishes a human-readable `sha-<full-commit>` tag and reports the
immutable registry digest in its run summary. It never publishes `latest`.

To build the same reviewed source locally instead, give the result a commit-derived convenience tag:

```sh
docker build --pull --platform=linux/amd64 \
  --build-arg VERSION="$(git rev-parse HEAD)" \
  --tag "whalewall:$(git rev-parse --short=12 HEAD)" .
```

Local tags remain mutable. Push a local build to a registry and deploy the registry digest if this
GHCR workflow is not used.

Ensure whalewall is given necessary permissions, and that it is using `host` network mode. This
allows the whalewall container to modify host firewall rules.

An image digest, rather than a tag, should be used for deployment. The ready-to-use
[`deploy/compose.yml`](deploy/compose.yml) template is specifically for the image published by this
repository's GHCR workflow and requires its immutable digest through an environment variable.

If the GHCR package is private, authenticate the deployment host with a credential limited to
package reads before pulling (or make the package public):

```sh
printf '%s' "$GHCR_TOKEN" | docker login ghcr.io --username "$GHCR_USER" --password-stdin
unset GHCR_TOKEN
```

Never pass registry credentials or the host's Docker client configuration into the Whalewall
container. Then create the persistent state volume and deploy:

```sh
docker volume create whalewall_data
export WHALEWALL_IMAGE_DIGEST='<published-image-digest-without-the-sha256-prefix>'
docker compose -f deploy/compose.yml pull
docker compose -f deploy/compose.yml up -d
```

The fixed external volume prevents `docker compose down -v` from deleting Whalewall's ownership
database. The template also fixes the registry and `sha256:` prefix, so the environment variable
cannot replace the reviewed artifact with a mutable tag. Treat the checked-in template as
authoritative: its long bind syntax also refuses to create a directory when the Docker socket is
missing.

### First hardened deployment

Do not live-upgrade a running upstream Whalewall installation. Older per-container chains can contain
absolute `ACCEPT`, custom-chain, or NFQUEUE rules whose semantics are intentionally incompatible with
this fork.

For the first hardened deployment:

1. Stop the protected workloads.
2. Stop the old Whalewall process.
3. Run Whalewall's `-clear` operation using the same data directory as the old process.
4. Verify the `whalewall` chain, `whalewall-container-addrs` map, and all `whalewall-*` container
   chains are gone from `ip filter`.
5. Start the hardened build and verify its base rules and logs.
6. Start protected workloads one at a time, checking one allowed and one forbidden connection after
   each start.

If this is a new installation with no existing Whalewall rules or database, start at step 5.

### Binary install

This personal fork does not publish release binaries. Compile the checked-out source with the Go
version declared in `go.mod` and with cgo disabled. The runtime sandbox and container image are
audited for Linux on AMD64; other operating systems and architectures are intentionally unsupported:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildmode=pie -trimpath \
  -ldflags "-s -w -X main.version=$(git rev-parse HEAD)" \
  -o whalewall ./cmd/whalewall
```

After installing whalewall, grant it required permissions by running:

```sh
# this must be run first, it will erase any set capabilities
chgrp docker whalewall
setcap 'cap_net_admin=+ep' whalewall

```

## Configuration

Whalewall uses Docker labels for configuration:

- `whalewall.enabled` is used to enable or disable firewall rules for a container. If this label is
not present and set to `true` for a container, whalewall will not create any firewall rules for it.
- `whalewall.managed_networks` optionally limits enforcement to a comma-separated list of attached
Docker networks, for example `proxy` or `proxy,monitoring`. If it is absent, every attached network
is managed as before. Compose network keys are resolved against their project-prefixed Docker names.
- `whalewall.rules` specifies the firewall rules for a container. If this label is not specified but
`whalewall.enabled=true` is, no traffic will be allowed to or from the container (unless another
container has an output rule for this container).

The contents of the `whalewall.rules` label is a yaml config.

With a valid explicit network scope, only addresses on the selected networks enter Whalewall; other
attached networks pass through unchanged. A malformed, empty, duplicate, or unresolved scope is
treated as unsafe and quarantines every usable attached IPv4 address. Once the scope is valid, a
rules error quarantines only the selected networks.

Whalewall creates rules with a default drop policy, meaning any traffic not explicitly allowed will
be dropped. A Whalewall allow returns the packet to the remaining Docker and host firewall chains;
those downstream rules can still deny it. Whalewall does not override Docker bridge isolation.

Configuration is decoded strictly. In particular:

- `output` is a YAML list, so every rule starts with `-`.
- `container`, `containers`, and `ips` are mutually exclusive destination selectors. Empty
  selectors, blank container-list entries, and duplicate container-list entries are rejected.
- An output rule's `network` must be managed by the source. Named destinations must also manage the
  same concrete Docker network. Every member of a `containers` list is validated before any part of
  that policy is installed.
- Use the current `src_ports` and `dst_ports` list fields. The old singular `port` field is rejected.
- Ports and port-range endpoints must be between 1 and 65535; a range's start cannot exceed its end.
- IP addresses, CIDRs, and ranges must be IPv4. IPv6 values are rejected rather than partially
  configuring a policy.
- Publish host ports on an explicit IPv4 address, for example
  `0.0.0.0:443:443/tcp` or `127.0.0.1:8080:8080/tcp`. An IPv6 host binding such as `[::]:443:443`
  is rejected. Also keep Docker and every managed network's IPv6 setting disabled.
- Custom `verdict.chain` and NFQUEUE verdicts are rejected in this hardened fork. An `ACCEPT` from
  either path can terminate the host firewall hook before Docker's own bridge-isolation rules run.
- A broad IP rule such as `0.0.0.0/0` includes RFC1918, host, and Docker address ranges; it does not
  mean "public Internet only". Prefer named-container rules for peer traffic and explicit
  destination allowlists or a controlled egress proxy when that distinction matters.
- `mapped_ports` controls Docker-published host ports. Direct traffic between containers on a bridge
  network is allowed with an `output` rule that names the destination container. An unmanaged peer
  on the same bridge can also resemble "external" mapped-port traffic, so every member of a shared
  protected bridge must be managed or isolated on a separate edge network.

### Reverse proxy isolation

Keep the reverse proxy and backends on an ordinary user-defined bridge network. Do not run the proxy
with `network_mode: host`. Enable whalewall on the proxy and each protected backend, then allow only
the proxy's required destination ports. A minimal policy looks like this:

```yaml
services:
  caddy:
    cap_drop:
      # Docker includes NET_RAW by default. At minimum, remove it from every
      # workload sharing a protected bridge. Prefer ALL where the image permits.
      - NET_RAW
    security_opt:
      - no-new-privileges:true
    ports:
      - "0.0.0.0:80:80/tcp"
      - "0.0.0.0:443:443/tcp"
    labels:
      whalewall.enabled: "true"
      whalewall.managed_networks: "proxy"
      whalewall.rules: |
        mapped_ports:
          external:
            allow: true
        output:
          - network: proxy
            container: app
            proto: tcp
            dst_ports:
              - 8080
          # Also enumerate DNS, ACME, authentication, and any other
          # outbound connections required by this Caddy deployment.
    networks:
      - proxy

  app:
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    labels:
      # No app output rules: deny all app-initiated connections.
      whalewall.enabled: "true"
      whalewall.managed_networks: "proxy"
    networks:
      - proxy

networks:
  proxy:
    driver: bridge
    enable_ipv6: false
```

The proxy's output rule creates the corresponding established-return rule for `app`; do not add a
broad app-to-proxy rule. Backends sharing the same protocol and ports can be listed without changing
the policy semantics:

```yaml
output:
  - network: proxy
    containers:
      - authelia
      - jellyfin
      - homepage
    proto: tcp
    dst_ports:
      - 8080
```

Each list entry is resolved as an independent named-container rule, in the declared order, and one
invalid or unresolved entry rejects the complete policy. Confirm
`docker network inspect <actual-network-name> --format '{{.EnableIPv6}}'` prints `false`. Compose
normally prefixes the network key with its project name. For hostile workloads, replace the shared
`proxy` network with one bridge per Caddy-to-backend edge so unrelated services do not share a
layer-2 broadcast domain.

### Example

Below is an example Docker compose file that configures [Miniflux](https://github.com/miniflux/v2),
a feed reader. Miniflux needs to connect to a Postgresql database to store state and make outbound
HTTPS connections to fetch articles, so that's only what is allowed.

```yaml
version: "3"
services:
  miniflux:
    depends_on:
      - miniflux_db
    environment:
      - DATABASE_URL=postgres://miniflux:secret@miniflux_db/miniflux?sslmode=disable
      - RUN_MIGRATIONS=1
      - CREATE_ADMIN=1
      - ADMIN_USERNAME=admin
      - ADMIN_PASSWORD=password
    image: miniflux/miniflux:latest
    labels:
      whalewall.enabled: true
      whalewall.rules: |
        mapped_ports:
          # allow traffic to port 80 from localhost
          localhost:
            allow: true
          # allow traffic to port 80 from LAN
          external:
            allow: true
            ips:
              - "192.168.1.0/24"
        output:
          # allow postgres connections
          - network: default
            container: miniflux_db
            proto: tcp
            dst_ports:
              - 5432
          # allow DNS requests
          - log_prefix: "dns"
            proto: udp
            dst_ports:
              - 53
          # allow HTTPS requests
          - log_prefix: "https"
            proto: tcp
            dst_ports:
              - 443
    ports:
      - "0.0.0.0:80:8080/tcp"

  miniflux_db:
    environment:
      - POSTGRES_USER=miniflux
      - POSTGRES_PASSWORD=secret
    image: postgres:alpine
    labels:
      # no rules specified, drop all traffic
      whalewall.enabled: true
```

Note to make this Docker compose config as concise as possible, best practices were not followed.
This is merely intended to be an example of whalewall rules, not how to setup Miniflux securely.

### Rules config reference

```yaml
# controls traffic from localhost or external networks to a container on mapped ports
mapped_ports:
  # controls traffic from localhost
  localhost:
    # required; allow traffic from localhost or not 
    allow: false
    # optional; log new inbound traffic that this rule will match
    log_prefix: ""
  # controls traffic from external networks (from any non-loopback network interface)
  external:
    # required; allow external traffic or not
    allow: false
    # optional; log new inbound traffic that this rule will match
    log_prefix: ""
    # optional; a list of IP addresses, CIDRs, or ranges of IP addresses to allow traffic from
    ips: []
# controls traffic from a container to localhost, another container, or the internet
output:
    # optional; log new outbound traffic that this rule will match
  - log_prefix: ""
    # optional; a managed Docker network traffic will be allowed out of. If unset, defaults to all
    # networks selected by whalewall.managed_networks. Required for container/containers
    network: ""
    # optional destination selector; omit all three to match any destination, or set exactly one:
    # ips: [192.0.2.10, 198.51.100.0/24]
    # container: app
    # containers: [authelia, jellyfin, homepage]
    # required; either 'tcp' or 'udp'
    proto: ""
    # optional; a list of source ports to allow traffic to. Can be a single port or a
    # range of ports.
    src_ports: []
    # optional; a list of destination ports to allow traffic to. Can be a single port or a
    # range of ports.
    dst_ports: []
```

Port and IP ranges are inclusive. Examples:

- `4000-5000` will match all ports between and including port 4000 and port 5000
- `1.1.1.1-2.2.2.2` will match all IPs between and including 1.1.1.1 and 2.2.2.2

### Docker environmental variables

Whalewall accepts several environmental variables that can be used to configure how it connects to a Docker server:

- `DOCKER_HOST` to set the URL to the Docker server.
- `DOCKER_API_VERSION` to force a Docker API version. Leave it unset so negotiation can select API
  1.49 or newer; older APIs cannot report the firewall backend and are rejected.
- `DOCKER_CERT_PATH` to specify the directory from which to load the TLS certificates (ca.pem, cert.pem, key.pem).
- `DOCKER_TLS_VERIFY` to enable or disable TLS verification (off by default).

### Tips

- Logged traffic is sent to the kernel log file, typically `/var/log/kern.log` for Debian based distros
and `/var/log/messages` for RHEL based distros
- If you want a container to only be allowed outbound access on a port to localhost, use the IP
of the `docker0` network interface, which is often `172.17.0.1`
- If no Docker networks are explicitly created, use the `default` network when creating container to
container rules

### Operational verification

After startup and after every label, Docker, or network change:

```sh
docker logs whalewall
sudo nft list chain ip filter DOCKER-USER
sudo nft list table ip filter
```

Confirm there are no rule-creation errors, then probe at least one explicitly allowed connection and
one forbidden connection from every protected trust boundary. Re-run those probes after restarting
Docker, whalewall, the proxy, and one protected backend. A running whalewall process is not by itself
proof that every enabled container has an active policy.

## Supply-chain pinning

Pin deployments to the digest of an image built from a reviewed commit. A Git tag or mutable image
tag is useful for humans but is not an immutable deployment identity:

```yaml
services:
  whalewall:
    image: ghcr.io/andrei-isaev/whalewall@sha256:<reviewed-64-hex-digest>
```

Record the source commit and image digest together in the deployment repository. Rebuild and review
explicitly when either the Go dependencies or base image changes.

A Git submodule already records an immutable commit (the remote branch cannot silently change the
gitlink stored by the parent repository). For example, in the deployment repository:

```sh
git submodule add https://github.com/andrei-isaev/whalewall.git third_party/whalewall
git -C third_party/whalewall checkout <reviewed-commit>
git add .gitmodules third_party/whalewall
git commit -m 'Pin hardened whalewall'
```

Build from `third_party/whalewall`, then deploy the resulting image by digest rather than by its
mutable tag. A submodule is unnecessary when using the reviewed GHCR artifact; record its source
commit and image digest together in the deployment repository instead.
