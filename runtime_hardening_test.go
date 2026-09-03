package whalewall

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"
	"go.uber.org/zap"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/capnspacehook/whalewall/database"
)

const hardeningContainerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// handleMutatingFirewall mirrors google/nftables behavior: successful rule
// creation replies populate Handle on the exact Rule pointer submitted by the
// caller. The regular mock stores a copy, so this wrapper catches accidental
// reuse of a previously submitted rule as a new rule.
type handleMutatingFirewall struct {
	firewallClient
	pending    []*nftables.Rule
	nextHandle uint64
}

func (m *handleMutatingFirewall) AddRule(rule *nftables.Rule) *nftables.Rule {
	m.pending = append(m.pending, rule)
	return m.firewallClient.AddRule(rule)
}

func (m *handleMutatingFirewall) InsertRule(rule *nftables.Rule) *nftables.Rule {
	m.pending = append(m.pending, rule)
	return m.firewallClient.InsertRule(rule)
}

func (m *handleMutatingFirewall) Flush() error {
	if err := m.firewallClient.Flush(); err != nil {
		return err
	}
	for _, rule := range m.pending {
		m.nextHandle++
		rule.Handle = m.nextHandle
		rule.ID = 0
	}
	m.pending = nil
	return nil
}

func TestValidateBridgeNetfilter(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		readErr error
		wantErr bool
	}{
		{name: "enabled", value: "1\n"},
		{name: "disabled", value: "0\n", wantErr: true},
		{name: "invalid", value: "unexpected", wantErr: true},
		{name: "unavailable", readErr: errors.New("not found"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBridgeNetfilter(func(path string) ([]byte, error) {
				if path != bridgeNfCallIptables {
					t.Fatalf("unexpected path %q", path)
				}
				return []byte(tt.value), tt.readErr
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateBridgeNetfilter() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

type setRecordingFirewall struct {
	firewallClient
	set      *nftables.Set
	elements []nftables.SetElement
}

func (f *setRecordingFirewall) AddSet(set *nftables.Set, elements []nftables.SetElement) error {
	f.set = set
	f.elements = elements
	return nil
}

func TestCreateIPExprsUsesIPv4SetType(t *testing.T) {
	nfc := &setRecordingFirewall{}
	addrs := []addrOrRange{
		{addr: netip.MustParseAddr("192.0.2.10")},
		{addr: netip.MustParseAddr("198.51.100.20")},
	}
	chain := &nftables.Chain{Name: "test", Table: filterTable}

	if _, err := createIPExprs(nfc, addrs, dstAddrOffset, chain); err != nil {
		t.Fatalf("createIPExprs() error = %v", err)
	}
	if nfc.set == nil {
		t.Fatal("createIPExprs() did not create an anonymous set")
	}
	if nfc.set.KeyType != nftables.TypeIPAddr {
		t.Fatalf("anonymous set key type = %v, want %v", nfc.set.KeyType, nftables.TypeIPAddr)
	}
}

func TestPureSingletonSetsDeduplicateKeys(t *testing.T) {
	chain := &nftables.Chain{Name: "test", Table: filterTable}
	ip := netip.MustParseAddr("192.0.2.10")
	ipFirewall := &setRecordingFirewall{}
	if _, err := createIPExprs(ipFirewall, []addrOrRange{{addr: ip}, {addr: ip}}, dstAddrOffset, chain); err != nil {
		t.Fatalf("createIPExprs() error = %v", err)
	}
	if len(ipFirewall.elements) != 1 || !bytes.Equal(ipFirewall.elements[0].Key, []byte{192, 0, 2, 10}) {
		t.Fatalf("deduplicated IP elements = %#v", ipFirewall.elements)
	}

	portFirewall := &setRecordingFirewall{}
	if _, err := createPortExprs(portFirewall, []rulePorts{{single: 443}, {single: 443}}, dstPortOffset, chain); err != nil {
		t.Fatalf("createPortExprs() error = %v", err)
	}
	if len(portFirewall.elements) != 1 || binary.BigEndian.Uint16(portFirewall.elements[0].Key) != 443 {
		t.Fatalf("deduplicated port elements = %#v", portFirewall.elements)
	}
}

func TestContainerMappingVerdictDecodesKernelReadback(t *testing.T) {
	chainName := buildChainName("ignored", hardeningContainerID)
	verdictCode := int32(expr.VerdictGoto)
	encoded, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_VERDICT_CODE, Data: binary.BigEndian.AppendUint32(nil, uint32(verdictCode))},
		{Type: unix.NFTA_VERDICT_CHAIN, Data: []byte(chainName + "\x00")},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := containerMappingVerdict(nftables.SetElement{Val: encoded})
	if err != nil {
		t.Fatalf("containerMappingVerdict() error = %v", err)
	}
	if got.Kind != expr.VerdictGoto || got.Chain != chainName {
		t.Fatalf("decoded verdict = %#v", got)
	}
	if _, err := containerMappingVerdict(nftables.SetElement{VerdictData: &expr.Verdict{Kind: expr.VerdictAccept, Chain: chainName}}); err == nil {
		t.Fatal("absolute ACCEPT verdict was accepted as an address mapping")
	}
	if _, err := containerMappingVerdict(nftables.SetElement{VerdictData: &expr.Verdict{Kind: expr.VerdictGoto, Chain: whalewallChainName}}); err == nil {
		t.Fatal("non-container verdict target was accepted as an address mapping")
	}
	// Removing one byte can trim only netlink alignment padding. Truncate into
	// the declared chain attribute so the decoder must reject the message.
	if _, err := containerMappingVerdict(nftables.SetElement{Val: encoded[:len(encoded)-4]}); err == nil {
		t.Fatal("truncated kernel verdict was accepted")
	}
}

func TestContainerIDFromChainNameRejectsNonCanonicalTargets(t *testing.T) {
	canonicalID := strings.Repeat("a", 64)
	if got, err := containerIDFromChainName(chainPrefix + canonicalID); err != nil || got != canonicalID {
		t.Fatalf("canonical chain parsed as ID %q, error %v", got, err)
	}
	invalid := map[string]string{
		"short":     chainPrefix + strings.Repeat("a", 63),
		"long":      chainPrefix + strings.Repeat("a", 65),
		"non-hex":   chainPrefix + strings.Repeat("a", 63) + "g",
		"uppercase": chainPrefix + strings.Repeat("a", 63) + "A",
	}
	for name, chainName := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := containerIDFromChainName(chainName); err == nil {
				t.Fatalf("containerIDFromChainName(%q) unexpectedly succeeded", chainName)
			}
			if _, err := containerMappingVerdict(nftables.SetElement{VerdictData: &expr.Verdict{
				Kind: expr.VerdictGoto, Chain: chainName,
			}}); err == nil {
				t.Fatalf("containerMappingVerdict accepted noncanonical target %q", chainName)
			}
		})
	}
}

func TestLongContainerNamesCannotExceedNftLimits(t *testing.T) {
	longName := strings.Repeat("very-long-compose-service-", 20)
	chainName := buildChainName(longName, hardeningContainerID)
	if want := chainPrefix + hardeningContainerID; chainName != want {
		t.Fatalf("buildChainName() = %q, want %q", chainName, want)
	}
	if len(chainName) >= 256 {
		t.Fatalf("container chain name is too long: %d bytes", len(chainName))
	}

	logPrefix := formatLogPrefix(strings.Repeat("日志", 100), longName, hardeningContainerID)
	if len(logPrefix) > maxLogPrefixBytes {
		t.Fatalf("log prefix is %d bytes, want <= %d", len(logPrefix), maxLogPrefixBytes)
	}
	if strings.ToValidUTF8(logPrefix, "") != logPrefix {
		t.Fatal("log prefix truncation produced invalid UTF-8")
	}
	rawLog, ok := logExpr(strings.Repeat("x", 2*maxLogPrefixBytes)).(*expr.Log)
	if !ok {
		t.Fatal("logExpr() did not return an nftables log expression")
	}
	if len(rawLog.Data) > maxLogPrefixBytes {
		t.Fatalf("raw log expression prefix is %d bytes", len(rawLog.Data))
	}
}

func TestMixedAddressAndPortSetsUseMergedExclusiveIntervals(t *testing.T) {
	chain := &nftables.Chain{Name: "test", Table: filterTable}
	ipFirewall := &setRecordingFirewall{}
	_, err := createIPExprs(ipFirewall, []addrOrRange{
		{addr: netip.MustParseAddr("192.0.2.10")},
		{addrRange: netipx.MustParseIPRange("192.0.2.20-192.0.2.22")},
	}, dstAddrOffset, chain)
	if err != nil {
		t.Fatalf("createIPExprs() error = %v", err)
	}
	if !ipFirewall.set.Interval || len(ipFirewall.elements) != 4 {
		t.Fatalf("IP interval set = %#v %#v", ipFirewall.set, ipFirewall.elements)
	}
	wantIPs := [][]byte{{192, 0, 2, 10}, {192, 0, 2, 11}, {192, 0, 2, 20}, {192, 0, 2, 23}}
	for i, want := range wantIPs {
		if !bytes.Equal(ipFirewall.elements[i].Key, want) || ipFirewall.elements[i].IntervalEnd != (i%2 == 1) || len(ipFirewall.elements[i].KeyEnd) != 0 {
			t.Fatalf("IP element %d = %#v, want key %v end=%v", i, ipFirewall.elements[i], want, i%2 == 1)
		}
	}

	portFirewall := &setRecordingFirewall{}
	_, err = createPortExprs(portFirewall, []rulePorts{
		{single: 80},
		{interval: portInterval{min: 443, max: 444}},
		{single: 445}, // adjacent interval must merge through 445
	}, dstPortOffset, chain)
	if err != nil {
		t.Fatalf("createPortExprs() error = %v", err)
	}
	wantPorts := []uint16{80, 81, 443, 446}
	if !portFirewall.set.Interval || len(portFirewall.elements) != len(wantPorts) {
		t.Fatalf("port interval set = %#v %#v", portFirewall.set, portFirewall.elements)
	}
	for i, want := range wantPorts {
		if got := binary.BigEndian.Uint16(portFirewall.elements[i].Key); got != want || portFirewall.elements[i].IntervalEnd != (i%2 == 1) || len(portFirewall.elements[i].KeyEnd) != 0 {
			t.Fatalf("port element %d = %#v, want %d end=%v", i, portFirewall.elements[i], want, i%2 == 1)
		}
	}
}

func TestRuleFixtureUnionSetsHaveExactBounds(t *testing.T) {
	chain := &nftables.Chain{Name: "test", Table: filterTable}

	ipFirewall := &setRecordingFirewall{}
	_, err := createIPExprs(ipFirewall, []addrOrRange{
		{addr: netip.MustParseAddr("1.1.1.1")},
		{addrRange: netipx.RangeOfPrefix(netip.MustParsePrefix("192.168.1.0/24"))},
	}, dstAddrOffset, chain)
	if err != nil {
		t.Fatalf("createIPExprs() error = %v", err)
	}
	if ipFirewall.set == nil || !ipFirewall.set.Anonymous || !ipFirewall.set.Constant ||
		!ipFirewall.set.Interval || ipFirewall.set.KeyType != nftables.TypeIPAddr {
		t.Fatalf("IP union set schema = %#v", ipFirewall.set)
	}
	wantIPs := [][]byte{{1, 1, 1, 1}, {1, 1, 1, 2}, {192, 168, 1, 0}, {192, 168, 2, 0}}
	if len(ipFirewall.elements) != len(wantIPs) {
		t.Fatalf("IP union elements = %#v, want %d elements", ipFirewall.elements, len(wantIPs))
	}
	for i, want := range wantIPs {
		if !bytes.Equal(ipFirewall.elements[i].Key, want) ||
			ipFirewall.elements[i].IntervalEnd != (i%2 == 1) ||
			len(ipFirewall.elements[i].KeyEnd) != 0 {
			t.Fatalf("IP union element %d = %#v, want key %v end=%v", i, ipFirewall.elements[i], want, i%2 == 1)
		}
	}

	portFirewall := &setRecordingFirewall{}
	_, err = createPortExprs(portFirewall, []rulePorts{
		{single: 80},
		{interval: portInterval{min: 420, max: 9001}},
	}, dstPortOffset, chain)
	if err != nil {
		t.Fatalf("createPortExprs() error = %v", err)
	}
	if portFirewall.set == nil || !portFirewall.set.Anonymous || !portFirewall.set.Constant ||
		!portFirewall.set.Interval || portFirewall.set.KeyType != nftables.TypeInetService {
		t.Fatalf("port union set schema = %#v", portFirewall.set)
	}
	wantPorts := []uint16{80, 81, 420, 9002}
	if len(portFirewall.elements) != len(wantPorts) {
		t.Fatalf("port union elements = %#v, want %d elements", portFirewall.elements, len(wantPorts))
	}
	for i, want := range wantPorts {
		if got := binary.BigEndian.Uint16(portFirewall.elements[i].Key); got != want ||
			portFirewall.elements[i].IntervalEnd != (i%2 == 1) ||
			len(portFirewall.elements[i].KeyEnd) != 0 {
			t.Fatalf("port union element %d = %#v, want %d end=%v", i, portFirewall.elements[i], want, i%2 == 1)
		}
	}
}

func TestIntervalSetTopBoundaryUsesOpenEndedStart(t *testing.T) {
	chain := &nftables.Chain{Name: "test", Table: filterTable}
	portFirewall := &setRecordingFirewall{}
	_, err := createPortExprs(portFirewall, []rulePorts{
		{interval: portInterval{min: 1, max: 2}},
		{single: 65535},
	}, dstPortOffset, chain)
	if err != nil {
		t.Fatalf("createPortExprs() error = %v", err)
	}
	last := portFirewall.elements[len(portFirewall.elements)-1]
	if last.IntervalEnd || binary.BigEndian.Uint16(last.Key) != 65535 || len(last.KeyEnd) != 0 {
		t.Fatalf("top boundary = %#v, want open-ended 65535 start", last)
	}

	ipFirewall := &setRecordingFirewall{}
	allIPv4 := netipx.RangeOfPrefix(netip.MustParsePrefix("0.0.0.0/0"))
	_, err = createIPExprs(ipFirewall, []addrOrRange{{addrRange: allIPv4}, {addr: netip.MustParseAddr("192.0.2.1")}}, dstAddrOffset, chain)
	if err != nil {
		t.Fatalf("createIPExprs() error = %v", err)
	}
	if len(ipFirewall.elements) != 1 || ipFirewall.elements[0].IntervalEnd || !bytes.Equal(ipFirewall.elements[0].Key, []byte{0, 0, 0, 0}) {
		t.Fatalf("all-IPv4 interval elements = %#v", ipFirewall.elements)
	}
}

func TestHardenedBuildRejectsBypassingVerdicts(t *testing.T) {
	for _, tt := range []struct {
		name    string
		verdict verdict
	}{
		{name: "custom chain", verdict: verdict{Chain: "custom-accept"}},
		{name: "queue", verdict: verdict{Queue: 42}},
		{name: "input established queue", verdict: verdict{InputEstQueue: 42}},
		{name: "output established queue", verdict: verdict{OutputEstQueue: 42}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVerdict(tt.verdict)
			if err == nil || !strings.Contains(err.Error(), "unsupported in this hardened build") {
				t.Fatalf("validateVerdict() error = %v, want hardened-build rejection", err)
			}
		})
	}
}

func TestInvalidPolicyLeavesContainerFailClosed(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	container := hardeningContainer(map[string]string{
		enabledLabel: "true",
		rulesLabel:   "unknown_field: true",
	})

	err := r.createContainerRules(context.Background(), container, true)
	if err == nil || !strings.Contains(err.Error(), "error parsing rules") {
		t.Fatalf("createContainerRules() error = %v, want parsing error", err)
	}

	chainName := buildChainName("hardening", hardeningContainerID)
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		containerChain, ok := base.chains[chainName]
		if !ok {
			t.Fatalf("fail-closed chain %q was not created", chainName)
		}
		dropRule := createDropRule(containerChain.Chain, hardeningContainerID)
		if len(containerChain.Rules) != 1 || !rulesEqual(zap.NewNop(), containerChain.Rules[0], dropRule) {
			t.Fatalf("container chain rules = %#v, want only terminal drop", containerChain.Rules)
		}

		elems := base.tables[filterTableName].Sets[containerAddrSetName]
		wantAddr := netip.MustParseAddr("172.30.0.2").As4()
		if len(elems) != 1 || !bytes.Equal(elems[0].Key, wantAddr[:]) {
			t.Fatalf("container address map = %#v, want %v", elems, wantAddr)
		}
		if elems[0].VerdictData == nil || elems[0].VerdictData.Kind != expr.VerdictGoto {
			t.Fatalf("container address verdict = %#v, want goto", elems[0].VerdictData)
		}
	})

	if err := r.deleteContainerRules(context.Background(), hardeningContainerID, "hardening"); err != nil {
		t.Fatalf("deleteContainerRules() error = %v", err)
	}
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		if _, ok := base.chains[chainName]; ok {
			t.Fatalf("quarantine chain %q remains after deletion", chainName)
		}
		if elems := base.tables[filterTableName].Sets[containerAddrSetName]; len(elems) != 0 {
			t.Fatalf("container address map remains after deletion: %#v", elems)
		}
	})
	if _, err := r.db.GetContainerName(context.Background(), hardeningContainerID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetContainerName() error = %v, want sql.ErrNoRows", err)
	}
}

func TestExistingContainerChainIsQuarantinedAtHeadBeforeReconcile(t *testing.T) {
	_, firewallCreator := newHardeningTestManager(t)
	chainName := buildChainName("hardening", hardeningContainerID)
	nfc := firewallCreator.newMockFirewall()
	chain := &nftables.Chain{Name: chainName, Table: filterTable, Type: nftables.ChainTypeFilter}
	nfc.AddChain(chain)
	nfc.AddRule(&nftables.Rule{
		Table: filterTable, Chain: chain,
		Exprs: []expr.Any{&expr.Counter{}, allowReturnVerdict}, UserData: []byte(hardeningContainerID),
	})
	nfc.AddRule(createDropRule(chain, hardeningContainerID))
	if err := nfc.Flush(); err != nil {
		t.Fatal(err)
	}

	if err := ensureContainerDropPolicy(firewallCreator.newMockFirewall(), zap.NewNop(), chain, hardeningContainerID, true); err != nil {
		t.Fatalf("ensureContainerDropPolicy() error = %v", err)
	}
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		got := base.chains[chainName].Rules
		if len(got) != 3 || !containsVerdict(got[0].Exprs, expr.VerdictDrop) || !containsVerdict(got[1].Exprs, expr.VerdictReturn) {
			t.Fatalf("existing chain was not quarantined at head: %#v", got)
		}
	})
}

func TestPeriodicReconcileDoesNotPrependTransientDrop(t *testing.T) {
	_, firewallCreator := newHardeningTestManager(t)
	chainName := buildChainName("hardening", hardeningContainerID)
	nfc := firewallCreator.newMockFirewall()
	chain := &nftables.Chain{Name: chainName, Table: filterTable, Type: nftables.ChainTypeFilter}
	nfc.AddChain(chain)
	nfc.AddRule(&nftables.Rule{Table: filterTable, Chain: chain, Exprs: []expr.Any{&expr.Counter{}, allowReturnVerdict}, UserData: []byte(hardeningContainerID)})
	nfc.AddRule(createDropRule(chain, hardeningContainerID))
	if err := nfc.Flush(); err != nil {
		t.Fatal(err)
	}
	var handles []uint64
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		for _, rule := range base.chains[chainName].Rules {
			handles = append(handles, rule.Handle)
		}
	})
	if err := ensureContainerDropPolicy(firewallCreator.newMockFirewall(), zap.NewNop(), chain, hardeningContainerID, false); err != nil {
		t.Fatal(err)
	}
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		got := base.chains[chainName].Rules
		if len(got) != 2 || got[0].Handle != handles[0] || got[1].Handle != handles[1] {
			t.Fatalf("periodic floor check churned rules: %#v", got)
		}
	})
}

func TestPolicyReplacementDoesNotReuseMutatedEnforcementFloor(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	r.newFirewallClient = func() (firewallClient, error) {
		return &handleMutatingFirewall{firewallClient: firewallCreator.newMockFirewall()}, nil
	}

	if err := r.createContainerRules(context.Background(), hardeningContainer(map[string]string{enabledLabel: "true"}), true); err != nil {
		t.Fatalf("createContainerRules() with handle mutation: %v", err)
	}

	chainName := buildChainName("hardening", hardeningContainerID)
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		chain := base.chains[chainName]
		if len(chain.Rules) != 1 || !containsVerdict(chain.Rules[0].Exprs, expr.VerdictDrop) {
			t.Fatalf("authoritative policy = %#v, want one fresh terminal drop", chain.Rules)
		}
	})
}

func TestIPv6AttachmentIsRejectedAfterIPv4FloorInstalled(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := hardeningContainer(map[string]string{enabledLabel: "true"})
	cont.NetworkSettings.Networks["default"].GlobalIPv6Address = netip.MustParseAddr("2001:db8::2")

	err := r.createContainerRules(context.Background(), cont, true)
	if err == nil || !strings.Contains(err.Error(), "supports IPv4 only") {
		t.Fatalf("createContainerRules() error = %v, want IPv6 rejection", err)
	}

	chainName := buildChainName("hardening", hardeningContainerID)
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		containerChain, ok := base.chains[chainName]
		if !ok || len(containerChain.Rules) != 1 {
			t.Fatalf("IPv4 enforcement floor missing: chain=%v rules=%d", ok, len(containerChain.Rules))
		}
	})
}

func TestManagerCancellationPreservesEnforcementFloor(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := r.createContainerRules(ctx, hardeningContainer(map[string]string{enabledLabel: "true"}), true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("createContainerRules() error = %v, want context.Canceled", err)
	}

	chainName := buildChainName("hardening", hardeningContainerID)
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		containerChain, ok := base.chains[chainName]
		if !ok || len(containerChain.Rules) != 1 {
			t.Fatalf("manager cancellation removed enforcement floor: chain=%v rules=%d", ok, len(containerChain.Rules))
		}
		if elems := base.tables[filterTableName].Sets[containerAddrSetName]; len(elems) != 1 {
			t.Fatalf("manager cancellation removed address mapping: %#v", elems)
		}
	})
}

func TestInvalidEnabledLabelInstallsDenyOnlyPolicy(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := hardeningContainer(map[string]string{
		enabledLabel: "definitely-not-a-bool",
		rulesLabel: `output:
  - proto: tcp
    dst_ports: [443]`,
	})
	r.dockerCli = newMockDockerClient([]container.InspectResponse{cont})

	err := r.syncContainers(context.Background(), true)
	if err == nil || !strings.Contains(err.Error(), enabledLabel) {
		t.Fatalf("syncContainers() error = %v, want invalid enabled-label error", err)
	}

	chainName := buildChainName("hardening", hardeningContainerID)
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		containerChain, ok := base.chains[chainName]
		if !ok {
			t.Fatalf("deny-only chain %q was not created", chainName)
		}
		dropRule := createDropRule(containerChain.Chain, hardeningContainerID)
		if len(containerChain.Rules) != 1 || !rulesEqual(zap.NewNop(), containerChain.Rules[0], dropRule) {
			t.Fatalf("container chain rules = %#v, want only terminal drop", containerChain.Rules)
		}
	})
}

func TestWhalewallEnabledAcceptsOnlyBooleanLiterals(t *testing.T) {
	for _, value := range []string{"true", "TRUE", " true ", "false", "FaLsE", "\tfalse\n"} {
		t.Run("accepted_"+strings.TrimSpace(value), func(t *testing.T) {
			if _, err := whalewallEnabled(map[string]string{enabledLabel: value}); err != nil {
				t.Fatalf("whalewallEnabled(%q) error = %v", value, err)
			}
		})
	}
	for _, value := range []string{"", "~", "null", "yes", "no", "on", "off", "1", "0", `"true"`} {
		t.Run("rejected_"+value, func(t *testing.T) {
			if _, err := whalewallEnabled(map[string]string{enabledLabel: value}); err == nil {
				t.Fatalf("whalewallEnabled(%q) unexpectedly succeeded", value)
			}
		})
	}
}

func TestYAMLLikeInvalidEnabledValuesAreQuarantined(t *testing.T) {
	for _, value := range []string{"", "~", "null"} {
		t.Run(value, func(t *testing.T) {
			r, firewallCreator := newHardeningTestManager(t)
			cont := hardeningContainer(map[string]string{enabledLabel: value, rulesLabel: "output: [{proto: tcp, dst_ports: [443]}]"})
			r.dockerCli = newMockDockerClient([]container.InspectResponse{cont})
			if err := r.syncContainers(context.Background(), true); err == nil {
				t.Fatal("syncContainers() unexpectedly accepted invalid enabled value")
			}
			chainName := buildChainName("hardening", hardeningContainerID)
			firewallCreator.readBaseFirewall(func(base *mockFirewall) {
				chain := base.chains[chainName]
				if len(chain.Rules) != 1 || !containsVerdict(chain.Rules[0].Exprs, expr.VerdictDrop) {
					t.Fatalf("invalid enabled value left non-quarantine policy: %#v", chain.Rules)
				}
			})
		})
	}
}

func TestDockerFirewallBackendValidation(t *testing.T) {
	for _, tt := range []struct {
		name    string
		backend *system.FirewallInfo
		infoErr error
		wantErr bool
	}{
		{name: "iptables", backend: &system.FirewallInfo{Driver: "iptables"}},
		{name: "native nftables", backend: &system.FirewallInfo{Driver: "nftables"}, wantErr: true},
		{name: "missing", wantErr: true},
		{name: "old API", infoErr: errors.New("field unavailable"), wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			docker := newMockDockerClient(nil)
			docker.info.FirewallBackend = tt.backend
			docker.infoErr = tt.infoErr
			r := &RuleManager{dockerCli: docker}
			err := r.validateDockerFirewallBackend(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateDockerFirewallBackend() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSQLiteConnectionPragmasApplyToEveryConnection(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "multi.sqlite")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(2)
	ctx := context.Background()
	conn1, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()
	conn2, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	for i, conn := range []*sql.Conn{conn1, conn2} {
		var foreignKeys, busyTimeout int
		var journalMode string
		if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
			t.Fatal(err)
		}
		if foreignKeys != 1 || busyTimeout != 1000 || !strings.EqualFold(journalMode, "wal") {
			t.Fatalf("connection %d pragmas = foreign_keys:%d busy_timeout:%d journal_mode:%q", i, foreignKeys, busyTimeout, journalMode)
		}
	}
}

func TestBaseRepairPreservesOnlyValidatedOwnedDrops(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	nfc := firewallCreator.newMockFirewall()
	safeDrop := &nftables.Rule{
		Table: filterTable, Chain: whalewallChain, UserData: []byte(hardeningContainerID),
		Exprs: []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, &expr.Counter{}, dropVerdict},
	}
	unsafeAccept := &nftables.Rule{Table: filterTable, Chain: whalewallChain, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept}}}
	nfc.AddRule(safeDrop)
	nfc.AddRule(unsafeAccept)
	if err := nfc.Flush(); err != nil {
		t.Fatalf("seeding main chain: %v", err)
	}
	if err := r.createBaseRules(); err != nil {
		t.Fatalf("repairing base rules: %v", err)
	}
	var firstHandles []uint64
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		rules := base.chains[whalewallChainName].Rules
		if len(rules) != 3 || !rulesEqual(zap.NewNop(), rules[0], createSourceDispatcherRule()) || !rulesEqual(zap.NewNop(), rules[1], createDestinationDispatcherRule()) {
			t.Fatalf("main chain order = %#v, want src,dst,safe-drop", rules)
		}
		if !isSafeOwnedDropRule(rules[2]) {
			t.Fatalf("validated drop was not preserved: %#v", rules[2])
		}
		for _, rule := range rules {
			if containsVerdict(rule.Exprs, expr.VerdictAccept) {
				t.Fatalf("unsafe ACCEPT survived base repair: %#v", rule)
			}
			firstHandles = append(firstHandles, rule.Handle)
		}
	})
	if err := r.createBaseRules(); err != nil {
		t.Fatalf("second base reconciliation: %v", err)
	}
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		for i, rule := range base.chains[whalewallChainName].Rules {
			if rule.Handle != firstHandles[i] {
				t.Fatalf("idempotent repair replaced rule %d handle %d with %d", i, firstHandles[i], rule.Handle)
			}
		}
	})
}

func TestBaseRepairDoesNotReuseMutatedDispatcherRules(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	r.newFirewallClient = func() (firewallClient, error) {
		return &handleMutatingFirewall{firewallClient: firewallCreator.newMockFirewall()}, nil
	}

	removeDispatchers := func() {
		nfc := firewallCreator.newMockFirewall()
		rules, err := nfc.GetRules(filterTable, whalewallChain)
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range rules {
			if rulesEqual(zap.NewNop(), rule, createSourceDispatcherRule()) || rulesEqual(zap.NewNop(), rule, createDestinationDispatcherRule()) {
				if err := nfc.DelRule(rule); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := nfc.Flush(); err != nil {
			t.Fatal(err)
		}
	}

	for attempt := range 2 {
		removeDispatchers()
		if err := r.createBaseRules(); err != nil {
			t.Fatalf("dispatcher repair attempt %d: %v", attempt+1, err)
		}
	}
}

func TestBaseRepairRejectsLegacyJumpMappingWithoutMutation(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	nfc := firewallCreator.newMockFirewall()
	legacyChainName := "whalewall-legacy-" + hardeningContainerID[:12]
	legacyChain := &nftables.Chain{Name: legacyChainName, Table: filterTable, Type: nftables.ChainTypeFilter}
	nfc.AddChain(legacyChain)
	nfc.AddRule(createDropRule(legacyChain, hardeningContainerID))
	legacy := nftables.SetElement{
		Key:         []byte{172, 30, 0, 2},
		VerdictData: &expr.Verdict{Kind: expr.VerdictJump, Chain: legacyChainName},
	}
	if err := nfc.SetAddElements(containerAddressSet(), []nftables.SetElement{legacy}); err != nil {
		t.Fatal(err)
	}
	if err := nfc.Flush(); err != nil {
		t.Fatal(err)
	}

	if err := r.createBaseRules(); err == nil || !strings.Contains(err.Error(), "clear the old Whalewall") {
		t.Fatalf("createBaseRules() error = %v, want legacy-mapping rejection", err)
	}
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		elements := base.tables[filterTableName].Sets[containerAddrSetName]
		if len(elements) != 1 || elements[0].VerdictData == nil || elements[0].VerdictData.Kind != expr.VerdictJump {
			t.Fatalf("legacy mapping was mutated: %#v", elements)
		}
		if got := base.chains[legacyChainName].Rules; len(got) != 1 || !containsVerdict(got[0].Exprs, expr.VerdictDrop) {
			t.Fatalf("legacy chain was mutated: %#v", got)
		}
	})
	if err := r.Clear(context.Background(), ""); err != nil {
		t.Fatalf("hardened Clear() could not remove legacy state: %v", err)
	}
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		if _, ok := base.tables[filterTableName].Sets[containerAddrSetName]; ok {
			t.Fatal("legacy verdict map remains after Clear")
		}
		for name := range base.chains {
			if name == whalewallChainName || strings.HasPrefix(name, chainPrefix) {
				t.Fatalf("Whalewall chain %q remains after Clear", name)
			}
		}
	})
}

func TestContainerAddressSetSchemaComparisonUsesKernelSemantics(t *testing.T) {
	desired := containerAddressSet()
	kernelNormalized := *desired
	kernelNormalized.Table = &nftables.Table{Name: filterTableName, Family: nftables.TableFamilyIPv4}
	kernelNormalized.KeyType.Name = ""
	kernelNormalized.DataType.Name = ""
	for _, verdictBytes := range []uint32{8, 16} {
		kernelNormalized.DataType.Bytes = verdictBytes
		if !containerAddressSetSchemaEqual(&kernelNormalized, desired) {
			t.Fatalf("kernel-normalized verdict map with %d-byte verdict was rejected", verdictBytes)
		}
	}
	nonVerdictDesired := *desired
	nonVerdictDesired.DataType = nftables.TypeInteger
	nonVerdictActual := nonVerdictDesired
	nonVerdictActual.DataType.Bytes++
	if containerAddressSetSchemaEqual(&nonVerdictActual, &nonVerdictDesired) {
		t.Fatal("non-verdict map with an incompatible data width was accepted")
	}

	tests := []struct {
		name   string
		mutate func(*nftables.Set)
	}{
		{
			name: "wrong table family",
			mutate: func(set *nftables.Set) {
				set.Table = &nftables.Table{Name: filterTableName, Family: nftables.TableFamilyIPv6}
			},
		},
		{
			name: "wrong key type",
			mutate: func(set *nftables.Set) {
				set.KeyType = nftables.TypeIP6Addr
			},
		},
		{
			name: "wrong key width",
			mutate: func(set *nftables.Set) {
				set.KeyType.Bytes++
			},
		},
		{
			name: "wrong data type",
			mutate: func(set *nftables.Set) {
				set.DataType = nftables.TypeInteger
			},
		},
		{
			name: "dynamic set",
			mutate: func(set *nftables.Set) {
				set.Dynamic = true
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := kernelNormalized
			tt.mutate(&actual)
			if containerAddressSetSchemaEqual(&actual, desired) {
				t.Fatal("incompatible verdict map schema was accepted")
			}
		})
	}
}

func TestMappedPortsOnNetworkWithoutGatewayStillCreateExternalRules(t *testing.T) {
	rules, err := (&RuleManager{}).createPortMappingRules(
		&setRecordingFirewall{},
		zap.NewNop(),
		container.InspectResponse{
			ID: hardeningContainerID, Name: "/hardening",
			NetworkSettings: &container.NetworkSettings{
				Ports: network.PortMap{
					network.MustParsePort("80/tcp"): {{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "8080"}},
				},
				Networks: map[string]*network.EndpointSettings{
					"internal": {IPAddress: netip.MustParseAddr("172.31.0.2")},
				},
			},
		},
		"hardening",
		mappedPorts{External: externalRules{Allow: true}},
		map[string][]byte{"internal": {172, 31, 0, 2}},
		&nftables.Chain{Name: "container", Table: filterTable},
	)
	if err != nil {
		t.Fatalf("createPortMappingRules() error = %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("createPortMappingRules() returned no external mapped-port rules")
	}
	for _, rule := range rules {
		if containsVerdict(rule.Exprs, expr.VerdictAccept) {
			t.Fatalf("generated default allow rule contains absolute ACCEPT: %#v", rule)
		}
		if rule.Chain.Name == whalewallChainName {
			continue
		}
		if !containsVerdict(rule.Exprs, expr.VerdictReturn) {
			t.Fatalf("external mapped-port rule has no return verdict: %#v", rule)
		}
		return
	}
	t.Fatal("no container-chain external mapped-port rule was created")
}

func TestIPv6PublishedBindingIsRejectedAfterFloorInstalled(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := hardeningContainer(map[string]string{
		enabledLabel: "true",
		rulesLabel:   "mapped_ports:\n  external:\n    allow: true",
	})
	cont.NetworkSettings.Ports = network.PortMap{
		network.MustParsePort("443/tcp"): {{HostIP: netip.MustParseAddr("::"), HostPort: "8443"}},
	}
	err := r.createContainerRules(context.Background(), cont, true)
	if err == nil || !strings.Contains(err.Error(), "IPv6 published HostIP") {
		t.Fatalf("createContainerRules() error = %v, want IPv6 binding rejection", err)
	}
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		chain := base.chains[buildChainName("hardening", hardeningContainerID)]
		if len(chain.Rules) != 1 || !containsVerdict(chain.Rules[0].Exprs, expr.VerdictDrop) {
			t.Fatalf("IPv6 binding failure was not quarantined: %#v", chain.Rules)
		}
	})
}

type closedStreamDocker struct {
	dockerClient
	calls  int
	called chan struct{}
}

func (d *closedStreamDocker) Events(_ context.Context, _ client.EventsListOptions) (<-chan events.Message, <-chan error) {
	d.calls++
	select {
	case d.called <- struct{}{}:
	default:
	}
	messages := make(chan events.Message)
	errs := make(chan error)
	close(messages)
	close(errs)
	return messages, errs
}

func (d *closedStreamDocker) Ping(context.Context) (client.PingResult, error) {
	return client.PingResult{}, nil
}

func TestClosedDockerEventStreamDoesNotSpin(t *testing.T) {
	docker := &closedStreamDocker{called: make(chan struct{}, 1)}
	r := &RuleManager{
		logger:            zap.NewNop(),
		dockerCli:         docker,
		stopping:          make(chan struct{}),
		reconcileInterval: time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.watchDocker(ctx, time.Now())
	}()

	<-docker.called
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchDocker did not stop after context cancellation")
	}
	if docker.calls != 1 {
		t.Fatalf("Events() calls = %d, want 1 before reconnect backoff", docker.calls)
	}
}

func TestStartContinuesAfterCleanupFaultAndSecuresRunningContainer(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	staleID := strings.Repeat("f", 64)
	tx, err := r.db.Begin(context.Background(), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.AddContainer(context.Background(), staleID, "stale"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	cont := hardeningContainer(map[string]string{enabledLabel: "true"})
	docker := newMockDockerClient([]container.InspectResponse{cont})
	r.newDockerClient = func() (dockerClient, error) { return docker, nil }
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	assertAddressMappedToChain(t, firewallCreator, []byte{172, 30, 0, 2}, buildChainName("hardening", cont.ID))
	select {
	case <-r.Done():
		t.Fatal("manager stopped after recoverable cleanup fault")
	default:
	}
	cancel()
	r.Stop()
}

func TestIPReuseReplacesVerdictAndDestinationCleanupScansSourceChains(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	sourceID := strings.Repeat("a", 64)
	oldDestinationID := strings.Repeat("b", 64)
	newDestinationID := strings.Repeat("c", 64)

	if err := r.createContainerRules(context.Background(), hardeningContainerWith(sourceID, "source", "172.30.0.2", map[string]string{enabledLabel: "true"}), true); err != nil {
		t.Fatalf("creating source policy: %v", err)
	}
	if err := r.createContainerRules(context.Background(), hardeningContainerWith(oldDestinationID, "old-destination", "172.30.0.3", map[string]string{enabledLabel: "true"}), true); err != nil {
		t.Fatalf("creating old destination policy: %v", err)
	}

	// Model the outbound source rule used for a destination-specific allow.
	nfc := firewallCreator.newMockFirewall()
	sourceChain := &nftables.Chain{Name: buildChainName("source", sourceID), Table: filterTable}
	nfc.InsertRule(&nftables.Rule{
		Table:    filterTable,
		Chain:    sourceChain,
		Exprs:    []expr.Any{&expr.Counter{}, allowReturnVerdict},
		UserData: []byte(oldDestinationID),
	})
	if err := nfc.Flush(); err != nil {
		t.Fatalf("adding destination-owned source rule: %v", err)
	}

	// Reuse the destination address before stale state has been cleaned. The
	// verdict map must be replaced, not accepted as EEXIST.
	newDestination := hardeningContainerWith(newDestinationID, "new-destination", "172.30.0.3", map[string]string{enabledLabel: "true"})
	originalDB := r.db
	r.db = &commitFailureDB{DB: originalDB}
	if err := r.createContainerRules(context.Background(), newDestination, true); !errors.Is(err, errInjectedCommit) {
		t.Fatalf("creating reused-address destination policy error = %v, want injected metadata failure", err)
	}
	r.db = originalDB
	wantChain := buildChainName("new-destination", newDestinationID)
	oldChainName := buildChainName("old-destination", oldDestinationID)
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		oldChain, ok := base.chains[oldChainName]
		if !ok {
			t.Fatalf("displaced chain %q was deleted instead of quarantined", oldChainName)
		}
		wantDrop := createDropRule(oldChain.Chain, oldDestinationID)
		if len(oldChain.Rules) != 1 || !rulesEqual(zap.NewNop(), wantDrop, oldChain.Rules[0]) {
			t.Fatalf("displaced chain rules = %#v, want exactly one canonical terminal DROP", oldChain.Rules)
		}
		for chainName, chain := range base.chains {
			for _, rule := range chain.Rules {
				if !bytes.Equal(rule.UserData, []byte(oldDestinationID)) {
					continue
				}
				if chainName == oldChainName && rulesEqual(zap.NewNop(), wantDrop, rule) {
					continue
				}
				t.Fatalf("stale old-destination rule remains in chain %q before explicit delete: %#v", chainName, rule)
			}
		}
		elems := base.tables[filterTableName].Sets[containerAddrSetName]
		for _, elem := range elems {
			if bytes.Equal(elem.Key, []byte{172, 30, 0, 3}) {
				if elem.VerdictData == nil || elem.VerdictData.Chain != wantChain {
					t.Fatalf("reused address points to %#v, want chain %q", elem.VerdictData, wantChain)
				}
				return
			}
		}
		t.Fatal("reused destination address is missing from verdict map")
	})

	if err := r.deleteContainerRules(context.Background(), oldDestinationID, "old-destination"); err != nil {
		t.Fatalf("deleting old destination: %v", err)
	}
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		for _, rule := range base.chains[sourceChain.Name].Rules {
			if bytes.Equal(rule.UserData, []byte(oldDestinationID)) {
				t.Fatal("destination-owned allow rule remains in source chain")
			}
		}
		elems := base.tables[filterTableName].Sets[containerAddrSetName]
		for _, elem := range elems {
			if bytes.Equal(elem.Key, []byte{172, 30, 0, 3}) && elem.VerdictData != nil && elem.VerdictData.Chain == wantChain {
				return
			}
		}
		t.Fatal("deleting old owner removed the new owner's verdict mapping")
	})
	if err := r.createContainerRules(context.Background(), newDestination, true); err != nil {
		t.Fatalf("reconciling new destination after metadata recovery: %v", err)
	}
}

func TestSyncDoesNotGateFailClosedInstallOnContainerExistsRead(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := hardeningContainer(map[string]string{enabledLabel: "true"})
	r.dockerCli = newMockDockerClient([]container.InspectResponse{cont})
	r.db = &containerExistsFailureDB{DB: r.db}

	if err := r.syncContainers(context.Background(), true); err != nil {
		t.Fatalf("syncContainers() error = %v", err)
	}
	assertAddressMappedToChain(t, firewallCreator, []byte{172, 30, 0, 2}, buildChainName("hardening", cont.ID))
}

func TestMetadataFailuresLeaveAddressMappedToDropChain(t *testing.T) {
	for _, tt := range []struct {
		name string
		wrap func(database.DB) database.DB
	}{
		{
			name: "begin",
			wrap: func(db database.DB) database.DB { return &beginFailureDB{DB: db} },
		},
		{
			name: "write",
			wrap: func(db database.DB) database.DB { return &metadataFailureDB{DB: db} },
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, firewallCreator := newHardeningTestManager(t)
			cont := hardeningContainer(map[string]string{enabledLabel: "true"})
			r.db = tt.wrap(r.db)

			if err := r.createContainerRules(context.Background(), cont, true); err == nil {
				t.Fatal("createContainerRules() error = nil, want injected database failure")
			}
			chainName := buildChainName("hardening", cont.ID)
			assertAddressMappedToChain(t, firewallCreator, []byte{172, 30, 0, 2}, chainName)
			firewallCreator.readBaseFirewall(func(base *mockFirewall) {
				chain, ok := base.chains[chainName]
				if !ok || len(chain.Rules) != 1 || !containsVerdict(chain.Rules[0].Exprs, expr.VerdictDrop) {
					t.Fatalf("failed metadata policy was not quarantined: %#v", chain)
				}
			})
		})
	}
}

var errInjectedDatabase = errors.New("injected database failure")

type containerExistsFailureDB struct{ database.DB }

func (d *containerExistsFailureDB) ContainerExists(context.Context, string) (bool, error) {
	return false, errInjectedDatabase
}

type beginFailureDB struct{ database.DB }

func (d *beginFailureDB) Begin(context.Context, *zap.Logger) (database.TX, error) {
	return nil, errInjectedDatabase
}

type nameLookupFailureDB struct{ database.DB }

func (d *nameLookupFailureDB) GetContainerName(context.Context, string) (string, error) {
	return "", errInjectedDatabase
}

type metadataFailureDB struct{ database.DB }

func (d *metadataFailureDB) Begin(ctx context.Context, logger *zap.Logger) (database.TX, error) {
	tx, err := d.DB.Begin(ctx, logger)
	if err != nil {
		return nil, err
	}
	return &metadataFailureTX{TX: tx}, nil
}

type metadataFailureTX struct{ database.TX }

func (t *metadataFailureTX) AddContainer(context.Context, string, string) error {
	return errInjectedDatabase
}

func assertAddressMappedToChain(tb testing.TB, firewallCreator mockFirewallCreatorI, address []byte, chainName string) {
	tb.Helper()
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		for _, element := range base.tables[filterTableName].Sets[containerAddrSetName] {
			if bytes.Equal(element.Key, address) && element.VerdictData != nil && element.VerdictData.Chain == chainName {
				return
			}
		}
		tb.Fatalf("address %v is not mapped to chain %q", address, chainName)
	})
}

var errInjectedCommit = errors.New("injected database commit failure")

type commitFailureDB struct {
	database.DB
}

func (d *commitFailureDB) Begin(ctx context.Context, logger *zap.Logger) (database.TX, error) {
	tx, err := d.DB.Begin(ctx, logger)
	if err != nil {
		return nil, err
	}
	return &commitFailureTX{TX: tx}, nil
}

type commitFailureTX struct {
	database.TX
}

func (t *commitFailureTX) Commit() error {
	return errInjectedCommit
}

var errInjectedFlush = errors.New("injected nftables flush failure")

type flushFailureFirewall struct {
	firewallClient
	failing *bool
}

type blockingFlushFirewall struct {
	firewallClient
	once    *sync.Once
	entered chan struct{}
	release chan struct{}
}

func (f *blockingFlushFirewall) Flush() error {
	f.once.Do(func() {
		close(f.entered)
		<-f.release
	})
	return f.firewallClient.Flush()
}

func TestDieEventWaitsForDeletionBeforeRestartCanApply(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := hardeningContainer(map[string]string{enabledLabel: "true"})
	if err := r.createContainerRules(context.Background(), cont, true); err != nil {
		t.Fatal(err)
	}
	docker := newMockDockerClient([]container.InspectResponse{cont})
	r.dockerCli = docker
	once := new(sync.Once)
	entered, release := make(chan struct{}), make(chan struct{})
	r.newFirewallClient = func() (firewallClient, error) {
		return &blockingFlushFirewall{firewallClient: firewallCreator.newMockFirewall(), once: once, entered: entered, release: release}, nil
	}
	createDone, deleteDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(createDone); r.createRules(context.Background()) }()
	go func() { defer close(deleteDone); r.deleteRules(context.Background()) }()
	dieDone := make(chan struct{})
	go func() {
		defer close(dieDone)
		r.handleDockerEvent(context.Background(), events.Message{
			Type: events.ContainerEventType, Action: events.ActionDie,
			Actor: events.Actor{ID: hardeningContainerID, Attributes: map[string]string{"name": "hardening"}},
		})
	}()
	<-entered
	select {
	case <-dieDone:
		t.Fatal("die event acknowledged before firewall deletion completed")
	default:
	}
	close(release)
	<-dieDone
	r.handleDockerEvent(context.Background(), events.Message{Type: events.ContainerEventType, Action: events.ActionStart, Actor: events.Actor{ID: hardeningContainerID}})
	close(r.createCh)
	close(r.deleteCh)
	<-createDone
	<-deleteDone
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		chain := base.chains[buildChainName("hardening", hardeningContainerID)]
		if len(chain.Rules) != 1 || !containsVerdict(chain.Rules[0].Exprs, expr.VerdictDrop) {
			t.Fatalf("post-restart policy missing: %#v", chain.Rules)
		}
	})
}

func TestDeleteAfterCommittedCreatorRaceStillRemovesPolicy(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := hardeningContainer(map[string]string{enabledLabel: "true"})
	if err := r.createContainerRules(context.Background(), cont, true); err != nil {
		t.Fatal(err)
	}
	creatingCtx, finishCreator := r.containerTracker.StartCreatingContainer(context.Background(), cont.ID)
	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- r.deleteContainerRules(context.Background(), cont.ID, "hardening")
	}()
	select {
	case <-creatingCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("delete did not cancel the committed creator")
	}
	select {
	case err := <-deleteDone:
		t.Fatalf("delete completed before creator returned: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	finishCreator()
	if err := <-deleteDone; err != nil {
		t.Fatalf("deleteContainerRules() error = %v", err)
	}
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		if _, ok := base.chains[buildChainName("hardening", cont.ID)]; ok {
			t.Fatal("post-commit creator race left the container chain")
		}
		if len(base.tables[filterTableName].Sets[containerAddrSetName]) != 0 {
			t.Fatal("post-commit creator race left the address mapping")
		}
	})
}

func (f *flushFailureFirewall) Flush() error {
	if *f.failing {
		return errInjectedFlush
	}
	return f.firewallClient.Flush()
}

func TestDeleteRetainsDatabaseStateUntilFirewallCleanupSucceeds(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	container := hardeningContainer(map[string]string{enabledLabel: "true"})
	if err := r.createContainerRules(context.Background(), container, true); err != nil {
		t.Fatalf("createContainerRules() error = %v", err)
	}

	failing := true
	r.newFirewallClient = func() (firewallClient, error) {
		return &flushFailureFirewall{firewallClient: firewallCreator.newMockFirewall(), failing: &failing}, nil
	}
	err := r.deleteContainerRules(context.Background(), hardeningContainerID, "hardening")
	if !errors.Is(err, errInjectedFlush) {
		t.Fatalf("deleteContainerRules() error = %v, want injected failure", err)
	}
	if _, err := r.db.GetContainerName(context.Background(), hardeningContainerID); err != nil {
		t.Fatalf("database retry state was removed after firewall failure: %v", err)
	}

	failing = false
	if err := r.deleteContainerRules(context.Background(), hardeningContainerID, "hardening"); err != nil {
		t.Fatalf("retrying deleteContainerRules(): %v", err)
	}
	if _, err := r.db.GetContainerName(context.Background(), hardeningContainerID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetContainerName() error = %v, want sql.ErrNoRows after successful retry", err)
	}
}

func TestDeleteRemovesFirewallStateBeforeDatabaseBegin(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := hardeningContainer(map[string]string{enabledLabel: "true"})
	if err := r.createContainerRules(context.Background(), cont, true); err != nil {
		t.Fatal(err)
	}
	r.db = &beginFailureDB{DB: r.db}

	if err := r.deleteContainerRules(context.Background(), cont.ID, "hardening"); !errors.Is(err, errInjectedDatabase) {
		t.Fatalf("deleteContainerRules() error = %v, want injected database failure", err)
	}
	chainName := buildChainName("hardening", cont.ID)
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		if _, ok := base.chains[chainName]; ok {
			t.Fatalf("container chain %q remains after database failure", chainName)
		}
		for _, element := range base.tables[filterTableName].Sets[containerAddrSetName] {
			if bytes.Equal(element.Key, []byte{172, 30, 0, 2}) {
				t.Fatalf("address mapping remains after database failure: %#v", element)
			}
		}
	})
	if _, err := r.db.GetContainerName(context.Background(), cont.ID); err != nil {
		t.Fatalf("database retry state was not preserved: %v", err)
	}
}

func TestDieCleanupIsNotGatedOnContainerNameLookup(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := hardeningContainer(map[string]string{enabledLabel: "true"})
	if err := r.createContainerRules(context.Background(), cont, true); err != nil {
		t.Fatal(err)
	}
	r.db = &nameLookupFailureDB{DB: r.db}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.deleteRules(context.Background())
	}()
	result := make(chan error, 1)
	r.deleteCh <- deleteDetails{id: cont.ID, name: cont.Name, result: result}
	if err := <-result; !errors.Is(err, errInjectedDatabase) {
		t.Fatalf("delete result = %v, want preserved lookup error", err)
	}
	close(r.deleteCh)
	<-done
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		if _, ok := base.chains[buildChainName("hardening", cont.ID)]; ok {
			t.Fatal("firewall cleanup was skipped after database name lookup failure")
		}
	})
}

func TestFailedReconcileRemovesDestinationTaggedAllowsFromSourceChain(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	sourceID := strings.Repeat("d", 64)
	destinationID := strings.Repeat("e", 64)
	destination := hardeningContainerWith(destinationID, "destination", "172.30.0.3", map[string]string{enabledLabel: "true"})
	source := hardeningContainerWith(sourceID, "source", "172.30.0.2", map[string]string{
		enabledLabel: "true",
		rulesLabel: `output:
  - container: destination
    network: default
    proto: tcp
    dst_ports: [443]`,
	})
	r.dockerCli = newMockDockerClient([]container.InspectResponse{source, destination})

	if err := r.createContainerRules(context.Background(), destination, true); err != nil {
		t.Fatalf("creating destination policy: %v", err)
	}
	if err := r.createContainerRules(context.Background(), source, true); err != nil {
		t.Fatalf("creating source policy: %v", err)
	}

	source.Config = &container.Config{Labels: map[string]string{
		enabledLabel: "true",
		rulesLabel:   "unknown_field: true",
	}}
	if err := r.createContainerRules(context.Background(), source, false); err == nil {
		t.Fatal("invalid reconcile unexpectedly succeeded")
	}

	sourceChainName := buildChainName("source", sourceID)
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		sourceChain := base.chains[sourceChainName]
		dropRule := createDropRule(sourceChain.Chain, sourceID)
		if len(sourceChain.Rules) != 1 || !rulesEqual(zap.NewNop(), sourceChain.Rules[0], dropRule) {
			t.Fatalf("failed reconcile left permissive source rules: %#v", sourceChain.Rules)
		}
	})
}

func TestPolicyRevocationPrunesWaitingRowsAndCannotBeRecreated(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	sourceID := strings.Repeat("2", 64)
	destinationID := strings.Repeat("3", 64)
	destination := hardeningContainerWith(destinationID, "destination", "172.30.0.3", map[string]string{enabledLabel: "true"})
	source := hardeningContainerWith(sourceID, "source", "172.30.0.2", map[string]string{
		enabledLabel: "true",
		rulesLabel:   "output:\n  - container: destination\n    network: default\n    proto: tcp\n    dst_ports: [443]",
	})
	source.NetworkSettings.Networks["default"].NetworkID = "shared-id"
	destination.NetworkSettings.Networks["default"].NetworkID = "shared-id"
	r.dockerCli = newMockDockerClient([]container.InspectResponse{source, destination})
	if err := r.createContainerRules(context.Background(), destination, true); err != nil {
		t.Fatal(err)
	}
	if err := r.createContainerRules(context.Background(), source, true); err != nil {
		t.Fatal(err)
	}
	source.Config.Labels = map[string]string{enabledLabel: "true"}
	dockerCli, ok := r.dockerCli.(*mockDockerClient)
	if !ok {
		t.Fatalf("Docker client type = %T, want *mockDockerClient", r.dockerCli)
	}
	dockerCli.containers[0] = source
	if err := r.createContainerRules(context.Background(), source, false); err != nil {
		t.Fatalf("revoking source policy: %v", err)
	}
	if err := r.createContainerRules(context.Background(), destination, false); err != nil {
		t.Fatalf("destination reconcile after revoke: %v", err)
	}
	rows, err := r.db.GetWaitingContainerRules(context.Background(), "destination")
	if err != nil || len(rows) != 0 {
		t.Fatalf("stale waiting rows = %#v, err=%v", rows, err)
	}
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		chain := base.chains[buildChainName("source", sourceID)]
		if len(chain.Rules) != 1 || !containsVerdict(chain.Rules[0].Exprs, expr.VerdictDrop) {
			t.Fatalf("revoked source policy returned: %#v", chain.Rules)
		}
	})
}

func TestComposeServiceResolutionUsesProjectAndNetworkIdentity(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	p1DstID, p2DstID, sourceID := strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64)
	makeContainer := func(id, name, project, networkName, networkID, address string, labels map[string]string) container.InspectResponse {
		if labels == nil {
			labels = make(map[string]string)
		}
		labels[enabledLabel] = "true"
		labels[composeProjectLabel] = project
		return container.InspectResponse{
			ID: id, Name: "/" + name, Config: &container.Config{Labels: labels},
			NetworkSettings: &container.NetworkSettings{Networks: map[string]*network.EndpointSettings{
				networkName: {NetworkID: networkID, Gateway: netip.MustParseAddr("172.30.0.1"), IPAddress: netip.MustParseAddr(address)},
			}},
		}
	}
	p1Dst := makeContainer(p1DstID, "p1-app-1", "p1", "p1_default", "p1-net", "172.30.0.3", map[string]string{composeServiceLabel: "app"})
	p2Dst := makeContainer(p2DstID, "p2-app-1", "p2", "p2_default", "p2-net", "172.31.0.3", map[string]string{composeServiceLabel: "app"})
	source := makeContainer(sourceID, "p1-source-1", "p1", "p1_default", "p1-net", "172.30.0.2", map[string]string{
		composeServiceLabel: "source",
		rulesLabel:          "output:\n  - container: app\n    network: default\n    proto: tcp\n    dst_ports: [443]",
	})
	// Deliberately list the other project's same-service container first.
	r.dockerCli = newMockDockerClient([]container.InspectResponse{p2Dst, p1Dst, source})
	if err := r.createContainerRules(context.Background(), p2Dst, true); err != nil {
		t.Fatal(err)
	}
	if err := r.createContainerRules(context.Background(), p1Dst, true); err != nil {
		t.Fatal(err)
	}
	if err := r.createContainerRules(context.Background(), source, true); err != nil {
		t.Fatalf("source policy: %v", err)
	}
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		rules := base.chains[buildChainName("p1-source-1", sourceID)].Rules
		for _, rule := range rules {
			if bytes.Equal(rule.UserData, []byte(p2DstID)) {
				t.Fatalf("source rule resolved to other project: %#v", rule)
			}
		}
		if !slices.ContainsFunc(rules, func(rule *nftables.Rule) bool { return bytes.Equal(rule.UserData, []byte(p1DstID)) }) {
			t.Fatalf("no rule resolved to p1 destination: %#v", rules)
		}
	})
}

func TestLegacyWaitingRuleWithoutIdentityCannotBindDuplicateService(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	sourceID, destinationID := strings.Repeat("7", 64), strings.Repeat("8", 64)
	source := hardeningContainerWith(sourceID, "p1-source", "172.30.0.2", map[string]string{
		enabledLabel: "true", composeProjectLabel: "p1", composeServiceLabel: "source",
	})
	destination := hardeningContainerWith(destinationID, "p2-app", "172.30.0.3", map[string]string{
		enabledLabel: "true", composeProjectLabel: "p2", composeServiceLabel: "app",
	})
	source.NetworkSettings.Networks["default"].NetworkID = "shared"
	destination.NetworkSettings.Networks["default"].NetworkID = "shared"
	r.dockerCli = newMockDockerClient([]container.InspectResponse{source, destination})
	if err := r.createContainerRules(context.Background(), source, true); err != nil {
		t.Fatal(err)
	}
	if err := r.createContainerRules(context.Background(), destination, true); err != nil {
		t.Fatal(err)
	}

	var encoded bytes.Buffer
	legacy := ruleConfig{Container: "app", Network: "default"}
	if err := gob.NewEncoder(&encoded).Encode(legacy); err != nil {
		t.Fatal(err)
	}
	tx, err := r.db.Begin(context.Background(), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.AddWaitingContainerRule(context.Background(), database.AddWaitingContainerRuleParams{
		SrcContainerID: sourceID, DstContainerName: "app", Rule: encoded.Bytes(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := r.createContainerRules(context.Background(), destination, false); err != nil {
		t.Fatalf("destination reconcile: %v", err)
	}
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		rules := base.chains[buildChainName("p2-app", destinationID)].Rules
		if len(rules) != 1 || !containsVerdict(rules[0].Exprs, expr.VerdictDrop) {
			t.Fatalf("legacy waiting row created an allow: %#v", rules)
		}
	})
}

type setReadBarrier struct {
	once     sync.Once
	snapshot chan struct{}
	release  chan struct{}
}

type barrierSetFirewall struct {
	firewallClient
	barrier *setReadBarrier
}

func (f *barrierSetFirewall) GetSetElements(set *nftables.Set) ([]nftables.SetElement, error) {
	elements, err := f.firewallClient.GetSetElements(set)
	f.barrier.once.Do(func() {
		close(f.barrier.snapshot)
		<-f.barrier.release
	})
	return elements, err
}

func TestConcurrentDeleteAndIPReuseSerializeVerdictMapOwnership(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	oldID := strings.Repeat("f", 64)
	newID := strings.Repeat("1", 64)
	oldContainer := hardeningContainerWith(oldID, "old-owner", "172.30.0.4", map[string]string{enabledLabel: "true"})
	newContainer := hardeningContainerWith(newID, "new-owner", "172.30.0.4", map[string]string{enabledLabel: "true"})
	if err := r.createContainerRules(context.Background(), oldContainer, true); err != nil {
		t.Fatalf("creating old owner: %v", err)
	}

	barrier := &setReadBarrier{snapshot: make(chan struct{}), release: make(chan struct{})}
	clientCreated := make(chan struct{}, 2)
	r.newFirewallClient = func() (firewallClient, error) {
		clientCreated <- struct{}{}
		return &barrierSetFirewall{firewallClient: firewallCreator.newMockFirewall(), barrier: barrier}, nil
	}
	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- r.deleteContainerRules(context.Background(), oldID, "old-owner")
	}()
	<-barrier.snapshot
	<-clientCreated // the deleting operation's client

	serialized := make(chan bool, 1)
	go func() {
		select {
		case <-clientCreated:
			// Without policy serialization, the creator reaches its firewall
			// client while deletion still holds the address-map snapshot.
			serialized <- false
		case <-time.After(100 * time.Millisecond):
			serialized <- true
		}
		close(barrier.release)
	}()
	// Run creation on this goroutine so it has definitely attempted the
	// policy critical section before the observer releases deletion.
	createErr := r.createContainerRules(context.Background(), newContainer, true)
	if !<-serialized {
		t.Fatal("new owner reached the firewall before old deletion completed")
	}
	if err := <-deleteDone; err != nil {
		t.Fatalf("deleting old owner: %v", err)
	}
	if createErr != nil {
		t.Fatalf("creating new owner: %v", createErr)
	}

	wantChain := buildChainName("new-owner", newID)
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		for _, element := range base.tables[filterTableName].Sets[containerAddrSetName] {
			if bytes.Equal(element.Key, []byte{172, 30, 0, 4}) && element.VerdictData != nil && element.VerdictData.Chain == wantChain {
				return
			}
		}
		t.Fatal("concurrent IP reuse ended without the new owner's verdict mapping")
	})
}

func TestDisabledContainerCleanupCannotDeleteReusedAddressOwner(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	protectedID := strings.Repeat("2", 64)
	disabledID := strings.Repeat("3", 64)
	protected := hardeningContainerWith(protectedID, "protected-owner", "172.30.0.4", map[string]string{enabledLabel: "true"})
	disabled := hardeningContainerWith(disabledID, "stale-disabled-owner", "172.30.0.4", map[string]string{enabledLabel: "false"})
	if err := r.createContainerRules(context.Background(), protected, true); err != nil {
		t.Fatalf("creating protected owner: %v", err)
	}

	// Model a delayed inspect/sync result for a disabled old container after
	// Docker has already reassigned its address to the protected container.
	r.dockerCli = newMockDockerClient([]container.InspectResponse{disabled})
	if err := r.syncContainers(context.Background(), false); err != nil {
		t.Fatalf("cleaning stale disabled owner: %v", err)
	}

	wantChain := buildChainName("protected-owner", protectedID)
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		for _, element := range base.tables[filterTableName].Sets[containerAddrSetName] {
			if bytes.Equal(element.Key, []byte{172, 30, 0, 4}) && element.VerdictData != nil && element.VerdictData.Chain == wantChain {
				return
			}
		}
		t.Fatal("disabled-container cleanup deleted the protected address owner")
	})
}

func TestReconcileDetachesStaleContainerAddressesAuthoritatively(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := hardeningContainer(map[string]string{enabledLabel: "true"})
	cont.NetworkSettings.Networks["monitoring"] = &network.EndpointSettings{
		NetworkID: "monitoring-id", Gateway: netip.MustParseAddr("172.31.0.1"), IPAddress: netip.MustParseAddr("172.31.0.2"),
	}
	cont.NetworkSettings.Networks["default"].NetworkID = "default-id"
	if err := r.createContainerRules(context.Background(), cont, true); err != nil {
		t.Fatalf("initial policy: %v", err)
	}
	delete(cont.NetworkSettings.Networks, "monitoring")
	if err := r.createContainerRules(context.Background(), cont, false); err != nil {
		t.Fatalf("detached-network reconcile: %v", err)
	}
	addrs, err := r.db.GetContainerAddrs(context.Background(), hardeningContainerID)
	if err != nil || len(addrs) != 1 || !bytes.Equal(addrs[0], []byte{172, 30, 0, 2}) {
		t.Fatalf("authoritative DB addresses = %#v, err=%v", addrs, err)
	}
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		elems := base.tables[filterTableName].Sets[containerAddrSetName]
		if len(elems) != 1 || !bytes.Equal(elems[0].Key, []byte{172, 30, 0, 2}) {
			t.Fatalf("authoritative verdict map = %#v", elems)
		}
	})
}

func TestNetworkDisconnectEventSynchronouslyReconcilesRunningContainer(t *testing.T) {
	r, firewallCreator := newHardeningTestManager(t)
	cont := hardeningContainer(map[string]string{enabledLabel: "true"})
	cont.State = &container.State{Running: true}
	cont.NetworkSettings.Networks["monitoring"] = &network.EndpointSettings{NetworkID: "monitoring-id", IPAddress: netip.MustParseAddr("172.31.0.2")}
	if err := r.createContainerRules(context.Background(), cont, true); err != nil {
		t.Fatal(err)
	}
	delete(cont.NetworkSettings.Networks, "monitoring")
	docker := newMockDockerClient([]container.InspectResponse{cont})
	r.dockerCli = docker
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); r.createRules(context.Background()) }()
	r.handleDockerEvent(context.Background(), events.Message{
		Type: events.NetworkEventType, Action: events.ActionDisconnect,
		Actor: events.Actor{ID: "monitoring-id", Attributes: map[string]string{"container": hardeningContainerID}},
	})
	close(r.createCh)
	<-workerDone
	firewallCreator.readBaseFirewall(func(base *mockFirewall) {
		elems := base.tables[filterTableName].Sets[containerAddrSetName]
		if len(elems) != 1 || !bytes.Equal(elems[0].Key, []byte{172, 30, 0, 2}) {
			t.Fatalf("disconnect event left stale mapping: %#v", elems)
		}
	})
}

func newHardeningTestManager(t *testing.T) (*RuleManager, mockFirewallCreatorI) {
	t.Helper()
	logger := zap.NewNop()
	r, err := NewRuleManager(context.Background(), logger, filepath.Join(t.TempDir(), "db.sqlite"), time.Second)
	if err != nil {
		t.Fatalf("NewRuleManager() error = %v", err)
	}
	t.Cleanup(func() {
		if err := r.db.Close(); err != nil {
			t.Errorf("closing database: %v", err)
		}
	})

	creator := newMockFirewallCreator(logger)
	nfc := creator.newMockFirewall()
	addMockDockerPrerequisites(t, nfc)
	r.newFirewallClient = func() (firewallClient, error) { return creator.newMockFirewall(), nil }
	if err := r.createBaseRules(); err != nil {
		t.Fatalf("createBaseRules() error = %v", err)
	}
	return r, creator
}

func addMockDockerPrerequisites(tb testing.TB, nfc firewallClient) {
	tb.Helper()
	nfc.AddTable(filterTable)
	dockerChain := &nftables.Chain{Name: dockerChainName, Table: filterTable, Type: nftables.ChainTypeFilter}
	forwardChain := &nftables.Chain{
		Name: forwardChainName, Table: filterTable, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter,
		Policy: ref(nftables.ChainPolicyAccept),
	}
	nfc.AddChain(dockerChain)
	nfc.AddChain(forwardChain)
	nfc.AddRule(createJumpRule(forwardChain, dockerChainName))
	if err := nfc.Flush(); err != nil {
		tb.Fatalf("creating mock Docker firewall prerequisites: %v", err)
	}
}

func hardeningContainer(labels map[string]string) container.InspectResponse {
	return hardeningContainerWith(hardeningContainerID, "hardening", "172.30.0.2", labels)
}

func hardeningContainerWith(id, name, address string, labels map[string]string) container.InspectResponse {
	return container.InspectResponse{
		ID: id, Name: "/" + name,
		Config: &container.Config{Labels: labels},
		NetworkSettings: &container.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"default": {Gateway: netip.MustParseAddr("172.30.0.1"), IPAddress: netip.MustParseAddr(address)},
			},
		},
	}
}

func containsVerdict(exprs []expr.Any, kind expr.VerdictKind) bool {
	for _, expression := range exprs {
		verdict, ok := expression.(*expr.Verdict)
		if ok && verdict.Kind == kind {
			return true
		}
	}
	return false
}
