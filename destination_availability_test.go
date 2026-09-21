package whalewall

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"go.uber.org/zap"
)

// Docker's running-only list can race with stop/removal before inspect.
type destinationAvailabilityDocker struct {
	*mockDockerClient
	inspectID  string
	inspectErr error
	listErr    error
}

func (d *destinationAvailabilityDocker) ContainerList(ctx context.Context, options client.ContainerListOptions) ([]container.Summary, error) {
	if d.listErr != nil {
		return nil, d.listErr
	}
	return d.mockDockerClient.ContainerList(ctx, options)
}

func (d *destinationAvailabilityDocker) ContainerInspect(ctx context.Context, id string) (container.InspectResponse, error) {
	if id == d.inspectID && d.inspectErr != nil {
		return container.InspectResponse{}, d.inspectErr
	}
	return d.mockDockerClient.ContainerInspect(ctx, id)
}

func TestDestinationAvailabilityLifecycle(t *testing.T) {
	for _, syntax := range []string{"containers: [authelia, immich-server, homepage]", "container: authelia\n  - network: proxy\n    container: immich-server\n  - network: proxy\n    container: homepage"} {
		for _, unavailable := range []string{"absent", "stopped during inspect", "removed during inspect"} {
			t.Run(syntax+"/"+unavailable, func(t *testing.T) {
				r, fw := newHardeningTestManager(t)
				ctx := context.Background()
				source := scopedTestContainer(scopeSourceID, "caddy", "172.30.0.2", "172.31.0.2", scopedEnabledLabels("caddy", "proxy"))
				source.Config.Labels[rulesLabel] = "output:\n  - network: proxy\n    " + syntax
				healthy := scopedTestContainer(scopeDest1ID, "authelia", "172.30.0.3", "172.31.0.3", scopedEnabledLabels("authelia", "proxy"))
				backend := scopedTestContainer(scopeDest2ID, "immich-server", "172.30.0.4", "172.31.0.4", scopedEnabledLabels("immich-server", "proxy"))
				other := scopedTestContainer(scopeDest3ID, "homepage", "172.30.0.5", "172.31.0.5", scopedEnabledLabels("homepage", "proxy"))
				docker := &destinationAvailabilityDocker{mockDockerClient: newMockDockerClient([]container.InspectResponse{source, healthy, backend, other})}
				r.dockerCli = docker
				for _, c := range []container.InspectResponse{healthy, backend, other, source} {
					if err := r.createContainerRules(ctx, c, true); err != nil {
						t.Fatal(err)
					}
				}
				assertCaddyDestinationOrder(t, fw, scopeDest1ID, scopeDest2ID, scopeDest3ID)
				var healthyRule *nftables.Rule
				fw.readBaseFirewall(func(base *mockFirewall) {
					healthyRule = base.chains[buildChainName("caddy", scopeSourceID)].Rules[0]
				})

				switch unavailable {
				case "absent":
					docker.containers = []container.InspectResponse{source, healthy, other}
				case "stopped during inspect":
					docker.containers[2].State = &container.State{Running: false}
				case "removed during inspect":
					docker.inspectID, docker.inspectErr = backend.ID, errdefs.ErrNotFound
				}
				// Reconcile before receiving the die event: stale destination metadata
				// must not keep the old IP allowance or quarantine unrelated peers.
				if err := r.createContainerRules(ctx, source, false); err != nil {
					t.Fatal(err)
				}
				assertCaddyDestinationOrder(t, fw, scopeDest1ID, scopeDest3ID)
				fw.readBaseFirewall(func(base *mockFirewall) {
					got := base.chains[buildChainName("caddy", scopeSourceID)].Rules[0]
					if !rulesEqual(zap.NewNop(), healthyRule, got) {
						t.Fatal("healthy backend rule changed when another backend disappeared")
					}
				})
				rows, err := r.db.GetWaitingContainerRules(ctx, "immich-server")
				if err != nil || len(rows) != 1 {
					t.Fatalf("missing waiting edge: rows=%v err=%v", rows, err)
				}
				if err := r.deleteContainerRules(ctx, backend.ID, "immich-server"); err != nil {
					t.Fatal(err)
				}
				assertCaddyDestinationOrder(t, fw, scopeDest1ID, scopeDest3ID)

				// A replacement has a different Docker identity and IP. Recovery
				// must bind the waiting edge to that identity, never the stale IP.
				backend.ID = strings.Repeat("e", 64)
				backend.NetworkSettings.Networks["demo_proxy"].IPAddress = netip.MustParseAddr("172.30.0.6")
				docker.inspectErr = nil
				docker.containers = []container.InspectResponse{source, healthy, backend, other}
				if err := r.createContainerRules(ctx, backend, true); err != nil {
					t.Fatalf("backend recovery: %v", err)
				}
				fw.readBaseFirewall(func(base *mockFirewall) {
					rules := base.chains[buildChainName("caddy", scopeSourceID)].Rules
					found := false
					for _, rule := range rules {
						if bytes.Equal(rule.UserData, []byte(scopeDest2ID)) {
							t.Fatal("recovery retained the removed backend identity")
						}
						if bytes.Equal(rule.UserData, []byte(backend.ID)) {
							found = true
							if !containsVerdict(rule.Exprs, expr.VerdictReturn) {
								t.Fatal("recovered rule does not allow the backend")
							}
							matchesNewIP := false
							for _, expression := range rule.Exprs {
								if comparison, ok := expression.(*expr.Cmp); ok && bytes.Equal(comparison.Data, []byte{172, 30, 0, 6}) {
									matchesNewIP = true
								}
							}
							if !matchesNewIP {
								t.Fatal("recovered rule does not match the replacement IP")
							}
						}
					}
					if !found {
						t.Fatal("backend start did not restore the waiting rule")
					}
				})
				if err := r.createContainerRules(ctx, source, false); err != nil {
					t.Fatal(err)
				}
				assertCaddyDestinationOrder(t, fw, scopeDest1ID, backend.ID, scopeDest3ID)
			})
		}
	}
}

func assertCaddyDestinationOrder(t *testing.T, fw mockFirewallCreatorI, want ...string) {
	t.Helper()
	fw.readBaseFirewall(func(base *mockFirewall) {
		rules := base.chains[buildChainName("caddy", scopeSourceID)].Rules
		var got []string
		for _, rule := range rules {
			if string(rule.UserData) != scopeSourceID {
				got = append(got, string(rule.UserData))
				if !containsVerdict(rule.Exprs, expr.VerdictReturn) {
					t.Fatal("destination rule is not an allow")
				}
			}
		}
		if !reflect.DeepEqual(got, want) || len(rules) != len(want)+1 || !containsVerdict(rules[len(rules)-1].Exprs, expr.VerdictDrop) {
			t.Fatalf("destination rules = %v, want %v followed by default drop (total rules %d)", got, want, len(rules))
		}
	})
}

func TestDestinationAPIFailureStillQuarantinesSource(t *testing.T) {
	for _, operation := range []string{"list", "inspect"} {
		t.Run(operation, func(t *testing.T) {
			r, fw := newHardeningTestManager(t)
			source := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.31.0.2", scopedEnabledLabels("source", "proxy"))
			source.Config.Labels[rulesLabel] = "output:\n  - network: proxy\n    containers: [authelia, missing]"
			destination := scopedTestContainer(scopeDest1ID, "authelia", "172.30.0.3", "172.31.0.3", scopedEnabledLabels("authelia", "proxy"))
			failure := errors.New("Docker API unavailable")
			docker := &destinationAvailabilityDocker{mockDockerClient: newMockDockerClient([]container.InspectResponse{source, destination})}
			if operation == "list" {
				docker.listErr = failure
			} else {
				docker.inspectID, docker.inspectErr = destination.ID, failure
			}
			r.dockerCli = docker
			if err := r.createContainerRules(context.Background(), source, true); !errors.Is(err, failure) {
				t.Fatalf("error = %v, want Docker API failure", err)
			}
			assertDropOnlyChain(t, fw, buildChainName("source", scopeSourceID), scopeSourceID)
		})
	}
}

func TestWaitingDestinationDoesNotHideInvalidPolicy(t *testing.T) {
	for _, invalid := range []string{"disabled", "unmanaged network", "invalid scope", "ambiguous", "malformed rule"} {
		t.Run(invalid, func(t *testing.T) {
			r, fw := newHardeningTestManager(t)
			source := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.31.0.2", scopedEnabledLabels("source", "proxy"))
			source.Config.Labels[rulesLabel] = "output:\n  - network: proxy\n    containers: [missing, authelia]"
			destination := scopedTestContainer(scopeDest1ID, "authelia", "172.30.0.3", "172.31.0.3", scopedEnabledLabels("authelia", "proxy"))
			containers := []container.InspectResponse{source, destination}
			var wantError string
			switch invalid {
			case "disabled":
				destination.Config.Labels[enabledLabel] = "false"
				wantError = "does not have whalewall enabled"
			case "unmanaged network":
				destination.Config.Labels[managedNetworksLabel] = "monitoring"
				wantError = "does not manage Docker network"
			case "invalid scope":
				destination.Config.Labels[managedNetworksLabel] = "missing"
				wantError = "invalid managed network scope"
			case "ambiguous":
				duplicate := destination
				duplicate.ID = scopeDest2ID
				containers = append(containers, duplicate)
				wantError = "ambiguous"
			case "malformed rule":
				source.Config.Labels[rulesLabel] += "\n    dst_ports: [443]"
				wantError = `"proto" must be set`
			}
			r.dockerCli = newMockDockerClient(containers)
			if err := r.createContainerRules(context.Background(), source, true); err == nil || !strings.Contains(err.Error(), wantError) {
				t.Fatalf("error = %v, want %q", err, wantError)
			}
			assertDropOnlyChain(t, fw, buildChainName("source", scopeSourceID), scopeSourceID)
			rows, err := r.db.GetWaitingContainerRules(context.Background(), "missing")
			if err != nil || len(rows) != 0 {
				t.Fatalf("invalid policy retained a waiting rule: rows=%v err=%v", rows, err)
			}
		})
	}
}
