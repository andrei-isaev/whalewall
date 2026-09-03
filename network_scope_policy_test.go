package whalewall

import (
	"bytes"
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"go.uber.org/zap"
)

const (
	scopeSourceID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	scopeDest1ID  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	scopeDest2ID  = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	scopeDest3ID  = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

func TestValidScopeWithInvalidRulesQuarantinesOnlySelectedNetwork(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.31.0.2", map[string]string{
		enabledLabel:         "true",
		managedNetworksLabel: "proxy",
		rulesLabel:           "unknown_field: true",
	})

	err := r.createContainerRules(context.Background(), cont, true)
	if err == nil || !strings.Contains(err.Error(), "error parsing rules") {
		t.Fatalf("createContainerRules() error = %v; want strict rules error", err)
	}
	assertMappedAddresses(t, firewallCreator, map[string]string{
		"172.30.0.2": buildChainName("source", scopeSourceID),
	})
	assertDropOnlyChain(t, firewallCreator, buildChainName("source", scopeSourceID), scopeSourceID)
	assertSourceDatabaseAddresses(t, r, "172.30.0.2")
}

func TestInvalidScopeQuarantinesEveryUsableAttachedNetwork(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value string
	}{
		{name: "unresolved", value: "missing"},
		{name: "empty token", value: "proxy,"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, firewallCreator := newHardeningTestManager(t)
			cont := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.31.0.2", map[string]string{
				enabledLabel:         "true",
				managedNetworksLabel: tt.value,
			})

			err := r.createContainerRules(context.Background(), cont, true)
			if err == nil || !strings.Contains(err.Error(), "invalid managed network scope") {
				t.Fatalf("createContainerRules() error = %v; want managed-scope error", err)
			}
			chainName := buildChainName("source", scopeSourceID)
			assertMappedAddresses(t, firewallCreator, map[string]string{
				"172.30.0.2": chainName,
				"172.31.0.2": chainName,
			})
			assertDropOnlyChain(t, firewallCreator, chainName, scopeSourceID)
			assertSourceDatabaseAddresses(t, r, "172.30.0.2", "172.31.0.2")
		})
	}
}

func TestInvalidSelectedEndpointQuarantinesEveryUsableAttachedNetwork(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.31.0.2", map[string]string{
		enabledLabel:         "true",
		managedNetworksLabel: "proxy",
	})
	cont.NetworkSettings.Networks["demo_proxy"].GlobalIPv6Address = netip.MustParseAddr("2001:db8::2")

	err := r.createContainerRules(context.Background(), cont, true)
	if err == nil || !strings.Contains(err.Error(), "invalid managed network scope") {
		t.Fatalf("createContainerRules() error = %v; want managed-scope error", err)
	}
	chainName := buildChainName("source", scopeSourceID)
	assertMappedAddresses(t, firewallCreator, map[string]string{
		"172.30.0.2": chainName,
		"172.31.0.2": chainName,
	})
	assertDropOnlyChain(t, firewallCreator, chainName, scopeSourceID)
	assertSourceDatabaseAddresses(t, r, "172.30.0.2", "172.31.0.2")
}

func TestOverlappingScopedAddressQuarantinesAndRecovers(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.30.0.2", map[string]string{
		enabledLabel:         "true",
		managedNetworksLabel: "proxy",
	})

	err := r.createContainerRules(context.Background(), cont, true)
	if err == nil || !strings.Contains(err.Error(), "share IPv4 address") {
		t.Fatalf("createContainerRules() error = %v; want unsafe-overlap error", err)
	}
	chainName := buildChainName("source", scopeSourceID)
	assertMappedAddresses(t, firewallCreator, map[string]string{"172.30.0.2": chainName})
	assertDropOnlyChain(t, firewallCreator, chainName, scopeSourceID)
	assertSourceDatabaseAddresses(t, r, "172.30.0.2")

	cont.NetworkSettings.Networks["demo_monitoring"].IPAddress = netip.MustParseAddr("172.31.0.2")
	if err := r.createContainerRules(context.Background(), cont, false); err != nil {
		t.Fatalf("recover valid managed scope: %v", err)
	}
	assertMappedAddresses(t, firewallCreator, map[string]string{"172.30.0.2": chainName})
	assertSourceDatabaseAddresses(t, r, "172.30.0.2")
}

func TestNarrowingScopeRemovesUnselectedAddressMapping(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.31.0.2", map[string]string{
		enabledLabel: "true",
	})
	if err := r.createContainerRules(context.Background(), cont, true); err != nil {
		t.Fatalf("initial all-network policy: %v", err)
	}
	chainName := buildChainName("source", scopeSourceID)
	assertMappedAddresses(t, firewallCreator, map[string]string{
		"172.30.0.2": chainName,
		"172.31.0.2": chainName,
	})

	cont.Config.Labels[managedNetworksLabel] = "proxy"
	if err := r.createContainerRules(context.Background(), cont, false); err != nil {
		t.Fatalf("narrowed policy: %v", err)
	}
	assertMappedAddresses(t, firewallCreator, map[string]string{"172.30.0.2": chainName})
	assertSourceDatabaseAddresses(t, r, "172.30.0.2")
}

func TestOutputRuleCannotReferenceUnmanagedNetwork(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.31.0.2", map[string]string{
		enabledLabel:         "true",
		managedNetworksLabel: "proxy",
		rulesLabel: `output:
  - network: monitoring
    proto: tcp
    dst_ports: [443]
`,
	})

	err := r.createContainerRules(context.Background(), cont, true)
	if err == nil || !strings.Contains(err.Error(), `network "monitoring" not found`) {
		t.Fatalf("createContainerRules() error = %v; want unmanaged-network rejection", err)
	}
	assertMappedAddresses(t, firewallCreator, map[string]string{
		"172.30.0.2": buildChainName("source", scopeSourceID),
	})
	assertDropOnlyChain(t, firewallCreator, buildChainName("source", scopeSourceID), scopeSourceID)
}

func TestContainerListCreatesOrderedIndependentRules(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	destinations := []container.InspectResponse{
		scopedTestContainer(scopeDest1ID, "authelia", "172.30.0.3", "172.31.0.3", scopedEnabledLabels("authelia", "proxy")),
		scopedTestContainer(scopeDest2ID, "jellyfin", "172.30.0.4", "172.31.0.4", scopedEnabledLabels("jellyfin", "proxy")),
		scopedTestContainer(scopeDest3ID, "homepage", "172.30.0.5", "172.31.0.5", scopedEnabledLabels("homepage", "proxy")),
	}
	source := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.31.0.2", map[string]string{
		enabledLabel:         "true",
		managedNetworksLabel: "proxy",
		composeProjectLabel:  "demo",
		composeServiceLabel:  "source",
		rulesLabel: `output:
  - network: proxy
    containers:
      - authelia
      - jellyfin
      - homepage
    proto: tcp
    dst_ports: [443]
`,
	})
	allContainers := append([]container.InspectResponse{source}, destinations...)
	r.dockerCli = newMockDockerClient(allContainers)
	for _, destination := range destinations {
		if err := r.createContainerRules(context.Background(), destination, true); err != nil {
			t.Fatalf("create destination %q policy: %v", destination.Name, err)
		}
	}
	if err := r.createContainerRules(context.Background(), source, true); err != nil {
		t.Fatalf("create list policy: %v", err)
	}

	wantOrder := []string{scopeDest1ID, scopeDest2ID, scopeDest3ID}
	var gotOrder []string
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		chain, ok := base.chains[buildChainName("source", scopeSourceID)]
		if !ok {
			t.Fatal("source chain does not exist")
		}
		for _, rule := range chain.Rules {
			owner := string(rule.UserData)
			if owner != scopeSourceID {
				gotOrder = append(gotOrder, owner)
			}
		}
	})
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("destination rule order = %q; want %q", gotOrder, wantOrder)
	}
}

func TestUnresolvedContainerListEntryFailsCompletePolicy(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	destination := scopedTestContainer(scopeDest1ID, "authelia", "172.30.0.3", "172.31.0.3", scopedEnabledLabels("authelia", "proxy"))
	source := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.31.0.2", map[string]string{
		enabledLabel:         "true",
		managedNetworksLabel: "proxy",
		composeProjectLabel:  "demo",
		composeServiceLabel:  "source",
		rulesLabel: `output:
  - network: proxy
    containers: [authelia, missing]
    proto: tcp
    dst_ports: [443]
`,
	})
	r.dockerCli = newMockDockerClient([]container.InspectResponse{source, destination})
	if err := r.createContainerRules(context.Background(), destination, true); err != nil {
		t.Fatalf("create destination policy: %v", err)
	}

	err := r.createContainerRules(context.Background(), source, true)
	if err == nil || !strings.Contains(err.Error(), `listed container "missing" could not be resolved`) {
		t.Fatalf("createContainerRules() error = %v; want unresolved list-entry error", err)
	}
	assertDropOnlyChain(t, firewallCreator, buildChainName("source", scopeSourceID), scopeSourceID)
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		destinationChain := base.chains[buildChainName("authelia", scopeDest1ID)]
		for _, rule := range destinationChain.Rules {
			if bytes.Equal(rule.UserData, []byte(scopeSourceID)) {
				t.Fatalf("partial source rule was installed in destination chain: %#v", rule)
			}
		}
	})
	waiting, queryErr := r.db.GetWaitingContainerRules(context.Background(), "authelia")
	if queryErr != nil {
		t.Fatalf("GetWaitingContainerRules() error = %v", queryErr)
	}
	if len(waiting) != 0 {
		t.Fatalf("failed list policy retained partial waiting rows: %#v", waiting)
	}
	established, queryErr := r.db.GetEstContainers(context.Background(), scopeSourceID)
	if queryErr != nil {
		t.Fatalf("GetEstContainers() error = %v", queryErr)
	}
	if len(established) != 0 {
		t.Fatalf("failed list policy retained partial established relationships: %#v", established)
	}
}

func TestNamedDestinationMustManageSharedNetwork(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	destination := scopedTestContainer(scopeDest1ID, "authelia", "172.30.0.3", "172.31.0.3", scopedEnabledLabels("authelia", "monitoring"))
	source := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.31.0.2", map[string]string{
		enabledLabel:         "true",
		managedNetworksLabel: "proxy",
		composeProjectLabel:  "demo",
		composeServiceLabel:  "source",
		rulesLabel: `output:
  - network: proxy
    container: authelia
    proto: tcp
    dst_ports: [443]
`,
	})
	r.dockerCli = newMockDockerClient([]container.InspectResponse{source, destination})
	if err := r.createContainerRules(context.Background(), destination, true); err != nil {
		t.Fatalf("create destination policy: %v", err)
	}

	err := r.createContainerRules(context.Background(), source, true)
	if err == nil || !strings.Contains(err.Error(), "does not manage Docker network") {
		t.Fatalf("createContainerRules() error = %v; want destination-scope rejection", err)
	}
	assertDropOnlyChain(t, firewallCreator, buildChainName("source", scopeSourceID), scopeSourceID)
}

func TestContainerListWaitingRuleHonorsDestinationScope(t *testing.T) {
	for _, tt := range []struct {
		name             string
		destinationScope string
		wantError        string
		wantPeerRule     bool
	}{
		{
			name:             "destination keeps shared scope",
			destinationScope: "proxy",
			wantPeerRule:     true,
		},
		{
			name:             "destination scope changes before processing",
			destinationScope: "monitoring",
			wantError:        "does not manage Docker network",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, firewallCreator := newHardeningTestManager(t)
			destination := scopedTestContainer(scopeDest1ID, "authelia", "172.30.0.3", "172.31.0.3", scopedEnabledLabels("authelia", "proxy"))
			source := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.31.0.2", map[string]string{
				enabledLabel:         "true",
				managedNetworksLabel: "proxy",
				composeProjectLabel:  "demo",
				composeServiceLabel:  "source",
				rulesLabel: `output:
  - network: proxy
    containers: [authelia]
    proto: tcp
    dst_ports: [443]
`,
			})
			docker := newMockDockerClient([]container.InspectResponse{source, destination})
			r.dockerCli = docker

			// The destination is running and validates, but has not yet been
			// processed into WhaleWall's database, so this persists a waiting
			// relationship rather than installing a partial allow.
			if err := r.createContainerRules(context.Background(), source, true); err != nil {
				t.Fatalf("create source waiting policy: %v", err)
			}
			assertDropOnlyChain(t, firewallCreator, buildChainName("source", scopeSourceID), scopeSourceID)

			destination.Config.Labels[managedNetworksLabel] = tt.destinationScope
			err := r.createContainerRules(context.Background(), destination, true)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("create destination policy error = %v; want %q", err, tt.wantError)
				}
			} else if err != nil {
				t.Fatalf("create destination policy: %v", err)
			}

			peerRuleFound := false
			firewallCreator.readBaseFirewall(func(base *mockFirewall) {
				chain := base.chains[buildChainName("source", scopeSourceID)]
				for _, rule := range chain.Rules {
					if bytes.Equal(rule.UserData, []byte(scopeDest1ID)) {
						peerRuleFound = true
					}
				}
			})
			if peerRuleFound != tt.wantPeerRule {
				t.Fatalf("destination peer rule present = %t; want %t", peerRuleFound, tt.wantPeerRule)
			}
			if !tt.wantPeerRule {
				assertDropOnlyChain(t, firewallCreator, buildChainName("source", scopeSourceID), scopeSourceID)
				assertDropOnlyChain(t, firewallCreator, buildChainName("authelia", scopeDest1ID), scopeDest1ID)
			}
		})
	}
}

func TestScopedMappedPortsDoNotGenerateGlobalOrUnselectedRules(t *testing.T) {
	cont := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.31.0.2", nil)
	cont.NetworkSettings.Ports = network.PortMap{
		network.MustParsePort("80/tcp"): {{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "8080"}},
	}
	managed := map[string]*network.EndpointSettings{"demo_proxy": cont.NetworkSettings.Networks["demo_proxy"]}
	rules, err := (&RuleManager{}).createPortMappingRules(
		&setRecordingFirewall{},
		zap.NewNop(),
		cont,
		"source",
		mappedPorts{External: externalRules{Allow: true}},
		managed,
		map[string][]byte{"demo_proxy": {172, 30, 0, 2}},
		&nftables.Chain{Name: "source", Table: filterTable},
		true,
	)
	if err != nil {
		t.Fatalf("createPortMappingRules() error = %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("scoped mapped-port rule count = %d; want localhost drop and two external rules for one selected endpoint", len(rules))
	}
	if !containsVerdict(rules[0].Exprs, expr.VerdictDrop) {
		t.Fatalf("first scoped mapped-port rule does not deny localhost before external allows: %#v", rules[0])
	}
	for i, rule := range rules {
		if rule.Chain.Name == whalewallChainName {
			t.Fatalf("explicit scope generated a global pre-DNAT rule: %#v", rule)
		}
		if i > 0 && containsVerdict(rule.Exprs, expr.VerdictDrop) {
			t.Fatalf("external allow rule #%d unexpectedly drops traffic: %#v", i, rule)
		}
	}
}

func TestScopedMappedPortsWithoutGatewayFailClosed(t *testing.T) {
	cont := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.31.0.2", nil)
	cont.NetworkSettings.Networks["demo_proxy"].Gateway = netip.Addr{}
	cont.NetworkSettings.Ports = network.PortMap{
		network.MustParsePort("80/tcp"): {{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "8080"}},
	}
	managed := map[string]*network.EndpointSettings{"demo_proxy": cont.NetworkSettings.Networks["demo_proxy"]}
	_, err := (&RuleManager{}).createPortMappingRules(
		&setRecordingFirewall{},
		zap.NewNop(),
		cont,
		"source",
		mappedPorts{External: externalRules{Allow: true}},
		managed,
		map[string][]byte{"demo_proxy": {172, 30, 0, 2}},
		&nftables.Chain{Name: "source", Table: filterTable},
		true,
	)
	if err == nil || !strings.Contains(err.Error(), "has no gateway") {
		t.Fatalf("createPortMappingRules() error = %v; want scoped gateway error", err)
	}
}

func TestNarrowingScopeRemovesLegacyGlobalMappedPortRules(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := scopedTestContainer(scopeSourceID, "source", "172.30.0.2", "172.31.0.2", map[string]string{
		enabledLabel: "true",
		rulesLabel: `mapped_ports:
  external:
    allow: true
`,
	})
	cont.NetworkSettings.Ports = network.PortMap{
		network.MustParsePort("80/tcp"): {{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "8080"}},
	}
	if err := r.createContainerRules(context.Background(), cont, true); err != nil {
		t.Fatalf("create legacy all-network mapped-port policy: %v", err)
	}
	assertMainChainOwnerRule(t, firewallCreator, scopeSourceID, true)

	cont.Config.Labels[managedNetworksLabel] = "proxy"
	if err := r.createContainerRules(context.Background(), cont, false); err != nil {
		t.Fatalf("narrow mapped-port policy: %v", err)
	}
	assertMainChainOwnerRule(t, firewallCreator, scopeSourceID, false)
}

func scopedTestContainer(id, name, proxyAddr, monitoringAddr string, labels map[string]string) container.InspectResponse {
	return container.InspectResponse{
		ID: id, Name: "/" + name,
		Config: &container.Config{Labels: labels},
		NetworkSettings: &container.NetworkSettings{Networks: map[string]*network.EndpointSettings{
			"demo_proxy": {
				NetworkID: "proxy-network-id",
				Gateway:   netip.MustParseAddr("172.30.0.1"),
				IPAddress: netip.MustParseAddr(proxyAddr),
			},
			"demo_monitoring": {
				NetworkID: "monitoring-network-id",
				Gateway:   netip.MustParseAddr("172.31.0.1"),
				IPAddress: netip.MustParseAddr(monitoringAddr),
			},
		}},
	}
}

func scopedEnabledLabels(service, scope string) map[string]string {
	return map[string]string{
		enabledLabel:         "true",
		managedNetworksLabel: scope,
		composeProjectLabel:  "demo",
		composeServiceLabel:  service,
	}
}

func assertMappedAddresses(t *testing.T, creator mockFirewallCreatorI, want map[string]string) {
	t.Helper()
	got := make(map[string]string)
	creator.readBaseFirewall(func(base *mockFirewall) {
		for _, element := range base.tables[filterTableName].Sets[containerAddrSetName] {
			addr, ok := netip.AddrFromSlice(element.Key)
			if !ok {
				t.Fatalf("invalid address-map key %v", element.Key)
			}
			if element.VerdictData == nil || element.VerdictData.Kind != expr.VerdictGoto {
				t.Fatalf("address-map value for %s = %#v; want goto", addr, element.VerdictData)
			}
			got[addr.String()] = element.VerdictData.Chain
		}
	})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("address mappings = %#v; want %#v", got, want)
	}
}

func assertDropOnlyChain(t *testing.T, creator mockFirewallCreatorI, chainName, id string) {
	t.Helper()
	creator.readBaseFirewall(func(base *mockFirewall) {
		chain, ok := base.chains[chainName]
		if !ok {
			t.Fatalf("chain %q does not exist", chainName)
		}
		if len(chain.Rules) != 1 || !rulesEqual(zap.NewNop(), chain.Rules[0], createDropRule(chain.Chain, id)) {
			t.Fatalf("chain %q rules = %#v; want one canonical drop", chainName, chain.Rules)
		}
	})
}

func assertSourceDatabaseAddresses(t *testing.T, r *RuleManager, want ...string) {
	t.Helper()
	rows, err := r.db.GetContainerAddrs(context.Background(), scopeSourceID)
	if err != nil {
		t.Fatalf("GetContainerAddrs() error = %v", err)
	}
	got := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		addr, ok := netip.AddrFromSlice(row)
		if !ok {
			t.Fatalf("invalid database address %v", row)
		}
		got[addr.String()] = struct{}{}
	}
	wantSet := make(map[string]struct{}, len(want))
	for _, addr := range want {
		wantSet[addr] = struct{}{}
	}
	if !reflect.DeepEqual(got, wantSet) {
		t.Fatalf("database addresses = %#v; want %#v", got, wantSet)
	}
}

func assertMainChainOwnerRule(t *testing.T, creator mockFirewallCreatorI, owner string, want bool) {
	t.Helper()
	found := false
	creator.readBaseFirewall(func(base *mockFirewall) {
		for _, rule := range base.chains[whalewallChainName].Rules {
			if bytes.Equal(rule.UserData, []byte(owner)) {
				found = true
			}
		}
	})
	if found != want {
		t.Fatalf("main-chain rule owned by %s present = %t; want %t", owner[:12], found, want)
	}
}
