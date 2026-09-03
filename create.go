package whalewall

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.yaml.in/yaml/v3"
	"golang.org/x/sys/unix"

	containerstate "github.com/capnspacehook/whalewall/container"
	"github.com/capnspacehook/whalewall/database"
)

const (
	hostNetworkName = "host"

	composeProjectLabel = "com.docker.compose.project"
	composeServiceLabel = "com.docker.compose.service"
	composeContNumLabel = "com.docker.compose.container-number"

	chainPrefix = "whalewall-"
	// Linux NF_LOG_PREFIXLEN is 128 bytes including the terminating NUL.
	maxLogPrefixBytes = 127

	srcAddrOffset = uint32(12)
	dstAddrOffset = uint32(16)
	srcPortOffset = uint32(0)
	dstPortOffset = uint32(2)

	stateNew    = expr.CtStateBitNEW
	stateEst    = expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED
	stateNewEst = stateNew | stateEst
)

var (
	localAddr          = netip.MustParseAddr("127.0.0.1")
	zeroUint32         = []byte{0, 0, 0, 0}
	allowReturnVerdict = &expr.Verdict{
		// Return to DOCKER-USER/INPUT/OUTPUT after Whalewall allows a
		// packet. An absolute ACCEPT here would bypass Docker's remaining
		// forwarding and bridge-isolation chains.
		Kind: expr.VerdictReturn,
	}
	dropVerdict = &expr.Verdict{
		Kind: expr.VerdictDrop,
	}
)

// createRules adds nftables rules for started containers.
func (r *RuleManager) createRules(ctx context.Context) {
	for c := range r.createCh {
		err := r.createContainerRules(ctx, c.container, c.isNew)
		if err != nil {
			r.logger.Error("error creating rules",
				zap.String("container.id", c.container.ID[:12]),
				zap.String("container.name", stripName(c.container.Name)),
				zap.Error(err),
			)
		}
		if c.result != nil {
			c.result <- err
		}
	}
}

// createContainerRules creates nftables rules for a container.
func (r *RuleManager) createContainerRules(ctx context.Context, container dockercontainer.InspectResponse, quarantineFirst bool) (retErr error) {
	ctx, cleanup := r.containerTracker.StartCreatingContainer(ctx, container.ID)
	defer cleanup()

	contName := stripName(container.Name)
	logger := r.logger.With(zap.String("container.id", container.ID[:12]), zap.String("container.name", contName))
	logger.Info("creating rules", zap.Bool("container.quarantine_first", quarantineFirst))

	// check that network settings are valid
	if container.NetworkSettings == nil {
		return fmt.Errorf("container %q has no network settings", contName)
	}
	if len(container.NetworkSettings.Networks) == 1 {
		if _, ok := container.NetworkSettings.Networks[hostNetworkName]; ok {
			return fmt.Errorf("container %q is using host networking, rules cannot be created for it", contName)
		}
	}
	if container.Config == nil {
		return fmt.Errorf("container %q has no configuration", contName)
	}

	// Collect the container's IPv4 addresses before changing nftables.
	addrs := make(map[string][]byte, len(container.NetworkSettings.Networks))
	var ipv6Networks []string
	for netName, netSettings := range container.NetworkSettings.Networks {
		if netSettings.GlobalIPv6Address.IsValid() {
			ipv6Networks = append(ipv6Networks, netName)
		}
		addr := netSettings.IPAddress
		if !addr.IsValid() {
			return fmt.Errorf("container %q has an invalid IP address on network %q", contName, netName)
		}
		if !addr.Is4() {
			return fmt.Errorf("unsupported IP address %q on network %q: Whalewall supports IPv4 only", addr, netName)
		}
		addrs[netName] = ref(addr.As4())[:]
	}

	// Rules generated for this source can be installed in peer-container
	// chains. Keep dependency snapshots, nftables changes, and rollback ordered
	// with destination deletion so a stale allow cannot survive IP reuse.
	r.policyMu.Lock()
	defer r.policyMu.Unlock()

	nfc, err := r.newFirewallClient()
	if err != nil {
		return fmt.Errorf("error creating netlink connection: %w", err)
	}

	// Create the container chain with its terminal drop rule in one nftables
	// transaction. The address map is populated only after the drop rule is in
	// place, so traffic can never be directed to an unprotected chain.
	contChainName := buildChainName(contName, container.ID)
	chain := &nftables.Chain{
		Name:  contChainName,
		Table: filterTable,
		Type:  nftables.ChainTypeFilter,
	}
	if err := ensureContainerDropPolicy(nfc, logger, chain, container.ID, quarantineFirst); err != nil {
		return err
	}

	// Any failure after the enforcement floor exists must remove every
	// permissive rule owned by this policy using a fresh netlink connection.
	// A failed connection can retain queued messages, so reusing it for
	// rollback could accidentally commit a partial policy.
	defer func() {
		if retErr == nil {
			return
		}
		containerDeleted := errors.Is(context.Cause(ctx), containerstate.ErrContainerDeleted)
		// if we are shutting down, don't delete rules
		select {
		case <-r.stopping:
			return
		default:
		}

		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if containerDeleted {
			logger.Info("rule creation canceled, deleting container enforcement floor")
			if err := r.deleteContainerRulesUntracked(cleanupCtx, container.ID, contName); err != nil {
				// The database row is intentionally retained on cleanup failure so
				// periodic reconciliation can retry it.
				logger.Error("error deleting canceled container policy", zap.Error(err))
				retErr = errors.Join(retErr, err)
			}
			return
		}

		logger.Warn("policy creation failed, quarantining container", zap.Error(retErr))
		if err := r.quarantineContainerPolicy(cleanupCtx, logger, chain, container.ID); err != nil {
			logger.Error("error quarantining failed policy", zap.Error(err))
			retErr = errors.Join(retErr, err)
		}
	}()
	service := container.Config.Labels[composeServiceLabel]
	if err := r.reconcileContainerMetadata(ctx, nfc, container.ID, contName, service, chain.Name, addrs); err != nil {
		return fmt.Errorf("error persisting fail-closed container metadata: %w", err)
	}
	if len(ipv6Networks) != 0 {
		return fmt.Errorf("container is attached to IPv6-enabled networks %q; Whalewall supports IPv4 only", ipv6Networks)
	}

	// Parse configuration only after the enforcement floor is active. Invalid
	// or unknown policy fields therefore deny traffic instead of silently
	// leaving the container unfiltered.
	var rulesCfg config
	cfg, configExists := container.Config.Labels[rulesLabel]
	if configExists {
		dec := yaml.NewDecoder(strings.NewReader(cfg))
		dec.KnownFields(true)
		if err := dec.Decode(&rulesCfg); err != nil {
			return fmt.Errorf("error parsing rules: %w", err)
		}
		if err := validateConfig(rulesCfg); err != nil {
			return fmt.Errorf("error validating rules: %w", err)
		}
	}

	// Use a separate transaction for policy relationships. Minimal container
	// metadata was already committed above so failed policy parsing can still
	// be cleaned up on a later die event.
	tx, err := r.db.Begin(ctx, logger)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := resetContainerPolicy(ctx, tx, container.ID); err != nil {
		return err
	}

	project := container.Config.Labels[composeProjectLabel]
	estContainers := make(map[string]struct{})
	if configExists {
		if err := r.populateOutputRules(ctx, tx, rulesCfg, container.ID, project, container.NetworkSettings.Networks, estContainers); err != nil {
			return fmt.Errorf("error validating rules: %w", err)
		}
	}
	desiredRules := make([]*nftables.Rule, 0)

	// create rules that allow traffic from another container to this
	// container if necessary that couldn't be created before
	logger.Debug("creating waiting rules")
	waitingRules, err := r.createWaitingContainerRules(ctx, nfc, logger, tx, container.ID, contName, service, project, container.NetworkSettings.Networks, chain, estContainers)
	if err != nil {
		return fmt.Errorf("error creating waiting output rules: %w", err)
	}
	desiredRules = append(desiredRules, waitingRules...)

	// if no rules were explicitly specified, only the rule that drops
	// traffic to/from the container will be added
	if configExists {
		// handle outbound rules
		logger.Debug("creating output rules")
		outputRules, err := r.createOutputRules(ctx, nfc, logger, tx, rulesCfg.Output, project, addrs, chain, contName, container.ID)
		if err != nil {
			return fmt.Errorf("error creating output rules: %w", err)
		}
		desiredRules = append(desiredRules, outputRules...)

		// handle port mapping rules
		logger.Debug("creating mapped port rules")
		portMapRules, err := r.createPortMappingRules(nfc, logger, container, contName, rulesCfg.MappedPorts, addrs, chain)
		if err != nil {
			return fmt.Errorf("error creating port mapping rules: %w", err)
		}
		desiredRules = append(desiredRules, portMapRules...)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := replaceContainerPolicy(nfc, logger, chain, container.ID, desiredRules); err != nil {
		return fmt.Errorf("error replacing container policy: %w", err)
	}

	logger.Debug("finalizing policy metadata")
	if err := r.finalizeContainerPolicy(ctx, tx, container.ID, estContainers); err != nil {
		return fmt.Errorf("error finalizing container policy metadata: %w", err)
	}

	return nil
}

func (r *RuleManager) reconcileContainerMetadata(ctx context.Context, nfc firewallClient, id, name, service, chainName string, addrs map[string][]byte) error {
	r.addressMapMu.Lock()
	defer r.addressMapMu.Unlock()

	desired := make([]nftables.SetElement, 0, len(addrs))
	for _, addr := range addrs {
		desired = append(desired, nftables.SetElement{
			Key: addr,
			VerdictData: &expr.Verdict{
				Kind:  expr.VerdictGoto,
				Chain: chainName,
			},
		})
	}
	if err := replaceContainerAddressMappings(nfc, desired, chainName); err != nil {
		return err
	}

	// Persist metadata only after every desired address is routed to the
	// already-installed terminal-drop chain. A database error must leave a
	// container quarantined, never merely leave an unreferenced drop chain.
	tx, err := r.db.Begin(ctx, r.logger)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := replaceContainerMetadata(ctx, tx, id, name, service, addrs); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error committing container metadata: %w", err)
	}
	return nil
}

// replaceContainerPolicy performs an authoritative, packet-atomic policy
// replacement. The container's own chain is rebuilt completely and rules
// owned by this source are removed from every other Whalewall chain before
// the desired policy is inserted in the same nftables transaction.
func replaceContainerPolicy(nfc firewallClient, logger *zap.Logger, ownChain *nftables.Chain, id string, desired []*nftables.Rule) error {
	chains, err := nfc.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("error listing IPv4 chains: %w", err)
	}

	ownedChains := make(map[string]*nftables.Chain)
	for _, chain := range chains {
		if chain.Table.Name != filterTableName {
			continue
		}
		if chain.Name == whalewallChainName || strings.HasPrefix(chain.Name, chainPrefix) {
			if err := validateRegularOwnedChain(chain); err != nil {
				return fmt.Errorf("unsafe Whalewall chain %q: %w", chain.Name, err)
			}
			ownedChains[chain.Name] = chain
		}
	}
	if _, ok := ownedChains[ownChain.Name]; !ok {
		return fmt.Errorf("container chain %q no longer exists", ownChain.Name)
	}

	idBytes := []byte(id)
	for name, chain := range ownedChains {
		current, err := nfc.GetRules(filterTable, chain)
		if err != nil {
			return fmt.Errorf("error getting rules of chain %q: %w", name, err)
		}
		for _, rule := range current {
			if name != ownChain.Name && !bytes.Equal(rule.UserData, idBytes) {
				continue
			}
			if err := nfc.DelRule(rule); err != nil {
				return fmt.Errorf("error deleting stale rule from chain %q: %w", name, err)
			}
		}
	}

	byChain := make(map[string][]*nftables.Rule)
	for _, rule := range desired {
		byChain[rule.Chain.Name] = append(byChain[rule.Chain.Name], rule)
	}
	for chainName, rules := range byChain {
		if chainName == ownChain.Name {
			for _, rule := range rules {
				nfc.AddRule(rule)
			}
			continue
		}
		if chainName == whalewallChainName {
			// The main chain's source/destination dispatchers stay at positions
			// 0/1. Generated localhost pre-DNAT rules are hardened DROP-only
			// rules and are appended after them.
			for _, rule := range rules {
				nfc.AddRule(rule)
			}
			continue
		}
		// Rules in peer/base chains must precede their terminal drop or
		// dispatcher rules. Insert in reverse to preserve generation order.
		for i := len(rules) - 1; i >= 0; i-- {
			nfc.InsertRule(rules[i])
		}
	}
	// Always recreate exactly one canonical terminal drop at the end of the
	// source chain. nftables mutates a submitted Rule with its kernel handle,
	// so this must be a fresh value rather than the rule used to establish the
	// earlier enforcement floor.
	nfc.AddRule(createDropRule(ownChain, id))
	if err := nfc.Flush(); err != nil {
		return fmt.Errorf("error flushing authoritative policy: %w", err)
	}
	logger.Debug("replaced container policy", zap.Int("rule.count", len(desired)))
	return nil
}

func (r *RuleManager) quarantineContainerPolicy(ctx context.Context, logger *zap.Logger, chain *nftables.Chain, id string) error {
	nfc, err := r.newFirewallClient()
	if err != nil {
		return fmt.Errorf("error creating fresh netlink connection for quarantine: %w", err)
	}
	firewallErr := replaceContainerPolicy(nfc, logger, chain, id, nil)
	databaseErr := r.clearContainerPolicyMetadata(ctx, id)
	return errors.Join(firewallErr, databaseErr)
}

// replaceContainerAddressMappings makes each desired address point to the
// current container chain. Replacing a stale verdict is performed as one
// nftables transaction, so IP reuse cannot retain an old chain target or pass
// through an unmapped window.
func replaceContainerAddressMappings(nfc firewallClient, desired []nftables.SetElement, chainName string) error {
	if _, err := containerIDFromChainName(chainName); err != nil {
		return fmt.Errorf("invalid desired container chain %q: %w", chainName, err)
	}
	set := containerAddressSet()
	current, err := nfc.GetSetElements(set)
	if err != nil {
		return fmt.Errorf("error listing container address mappings: %w", err)
	}

	desiredByKey := make(map[string]nftables.SetElement, len(desired))
	for _, element := range desired {
		desiredByKey[string(element.Key)] = element
	}

	var deleteElements, addElements []nftables.SetElement
	displaced := make(map[string]string)
	seenDesired := make(map[string]struct{}, len(desired))
	for _, existing := range current {
		verdict, err := containerMappingVerdict(existing)
		if err != nil {
			return fmt.Errorf("invalid container address mapping for key %x: %w", existing.Key, err)
		}
		existing.VerdictData = verdict
		wanted, ok := desiredByKey[string(existing.Key)]
		if ok {
			seenDesired[string(existing.Key)] = struct{}{}
			if verdictSetElementsEqual(existing, wanted) {
				continue
			}
			if verdict.Chain != chainName {
				oldID, err := containerIDFromChainName(verdict.Chain)
				if err != nil {
					return fmt.Errorf("invalid displaced container chain %q: %w", verdict.Chain, err)
				}
				displaced[verdict.Chain] = oldID
			}
			deleteElements = append(deleteElements, nftables.SetElement{Key: existing.Key})
			addElements = append(addElements, wanted)
			continue
		}
		if verdict.Chain == chainName {
			deleteElements = append(deleteElements, nftables.SetElement{Key: existing.Key})
		}
	}
	for _, desiredElement := range desired {
		if _, ok := seenDesired[string(desiredElement.Key)]; ok {
			continue
		}
		addElements = append(addElements, desiredElement)
	}
	if len(deleteElements) == 0 && len(addElements) == 0 {
		return nil
	}
	// An address can be reused before Docker's die event for the old owner has
	// been processed. Retargeting only the verdict map would leave peer allow
	// rules that still carry the old destination ID. Quarantine every displaced
	// chain and delete those stale edges in the same nftables batch as the map
	// replacement, so packets can observe only the old state or the fully
	// cleaned new state.
	if len(displaced) != 0 {
		if err := quarantineDisplacedContainerPolicies(nfc, displaced); err != nil {
			return err
		}
	}
	if len(deleteElements) != 0 {
		if err := nfc.SetDeleteElements(set, deleteElements); err != nil {
			return fmt.Errorf("error marshaling stale container address mappings: %w", err)
		}
	}
	if len(addElements) != 0 {
		if err := nfc.SetAddElements(set, addElements); err != nil {
			return fmt.Errorf("error marshaling container address mappings: %w", err)
		}
	}
	if err := nfc.Flush(); err != nil {
		return fmt.Errorf("error replacing container address mappings: %w", err)
	}
	return nil
}

func quarantineDisplacedContainerPolicies(nfc firewallClient, displaced map[string]string) error {
	chains, err := nfc.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("error listing IPv4 chains for reused-address cleanup: %w", err)
	}

	owned := make(map[string]*nftables.Chain)
	for _, chain := range chains {
		if chain.Table == nil || chain.Table.Name != filterTableName {
			continue
		}
		switch {
		case chain.Name == whalewallChainName:
		case strings.HasPrefix(chain.Name, chainPrefix):
			if _, err := containerIDFromChainName(chain.Name); err != nil {
				return fmt.Errorf("unsafe Whalewall chain-name collision %q: %w", chain.Name, err)
			}
		default:
			continue
		}
		if err := validateRegularOwnedChain(chain); err != nil {
			return fmt.Errorf("unsafe Whalewall chain %q during reused-address cleanup: %w", chain.Name, err)
		}
		owned[chain.Name] = chain
	}
	for chainName, oldID := range displaced {
		chain, ok := owned[chainName]
		if !ok {
			return fmt.Errorf("displaced container chain %q for ID %s no longer exists", chainName, oldID)
		}
		parsedID, err := containerIDFromChainName(chain.Name)
		if err != nil || parsedID != oldID {
			return fmt.Errorf("displaced container chain %q has inconsistent owner ID", chainName)
		}
	}

	displacedIDs := make(map[string]struct{}, len(displaced))
	for _, oldID := range displaced {
		displacedIDs[oldID] = struct{}{}
	}
	for chainName, chain := range owned {
		rules, err := nfc.GetRules(filterTable, chain)
		if err != nil {
			return fmt.Errorf("error getting rules of chain %q during reused-address cleanup: %w", chainName, err)
		}
		oldID, isDisplacedChain := displaced[chainName]
		for _, rule := range rules {
			_, isStaleEdge := displacedIDs[string(rule.UserData)]
			if !isDisplacedChain && !isStaleEdge {
				continue
			}
			if err := nfc.DelRule(rule); err != nil {
				return fmt.Errorf("error deleting stale rule from chain %q during reused-address cleanup: %w", chainName, err)
			}
		}
		if isDisplacedChain {
			// Do not delete the chain: an already-queued packet or an unrelated
			// stale reference must land on an unconditional deny policy.
			nfc.AddRule(createDropRule(chain, oldID))
		}
	}
	return nil
}

func verdictSetElementsEqual(a, b nftables.SetElement) bool {
	if !bytes.Equal(a.Key, b.Key) || (a.VerdictData == nil) != (b.VerdictData == nil) {
		return false
	}
	if a.VerdictData == nil {
		return true
	}
	return a.VerdictData.Kind == b.VerdictData.Kind && a.VerdictData.Chain == b.VerdictData.Chain
}

func containerMappingVerdict(element nftables.SetElement) (*expr.Verdict, error) {
	var verdict expr.Verdict
	if element.VerdictData != nil {
		verdict = *element.VerdictData
	} else {
		if len(element.Val) == 0 {
			return nil, errors.New("verdict data is missing")
		}
		decoder, err := netlink.NewAttributeDecoder(element.Val)
		if err != nil {
			return nil, fmt.Errorf("decode verdict attributes: %w", err)
		}
		decoder.ByteOrder = binary.BigEndian
		var haveCode, haveChain bool
		for decoder.Next() {
			switch decoder.Type() {
			case unix.NFTA_VERDICT_CODE:
				if haveCode {
					return nil, errors.New("duplicate verdict code")
				}
				haveCode = true
				verdict.Kind = expr.VerdictKind(int32(decoder.Uint32()))
			case unix.NFTA_VERDICT_CHAIN:
				if haveChain {
					return nil, errors.New("duplicate verdict chain")
				}
				haveChain = true
				verdict.Chain = decoder.String()
			default:
				return nil, fmt.Errorf("unexpected verdict attribute %d", decoder.Type())
			}
		}
		if err := decoder.Err(); err != nil {
			return nil, fmt.Errorf("decode verdict attributes: %w", err)
		}
		if !haveCode || !haveChain {
			return nil, errors.New("verdict code or chain is missing")
		}
	}
	if verdict.Kind != expr.VerdictGoto {
		return nil, fmt.Errorf("verdict kind is %d, want GOTO", verdict.Kind)
	}
	if _, err := containerIDFromChainName(verdict.Chain); err != nil {
		return nil, fmt.Errorf("verdict target %q is not a canonical owned container chain: %w", verdict.Chain, err)
	}
	return &verdict, nil
}

func containerIDFromChainName(name string) (string, error) {
	if !strings.HasPrefix(name, chainPrefix) {
		return "", fmt.Errorf("missing %q prefix", chainPrefix)
	}
	id := strings.TrimPrefix(name, chainPrefix)
	if len(id) != 64 {
		return "", fmt.Errorf("container ID has length %d, want 64", len(id))
	}
	for i := range len(id) {
		if (id[i] < '0' || id[i] > '9') && (id[i] < 'a' || id[i] > 'f') {
			return "", fmt.Errorf("container ID contains non-lowercase-hex byte %q at offset %d", id[i], i)
		}
	}
	return id, nil
}

// ensureContainerDropPolicy creates a container chain with its terminal drop
// rule atomically, or repairs a missing drop in an existing chain. A missing
// drop is inserted first so an unexpectedly populated chain fails closed.
func ensureContainerDropPolicy(nfc firewallClient, logger *zap.Logger, chain *nftables.Chain, id string, quarantineFirst bool) error {
	chains, err := nfc.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("error listing IPv4 chains: %w", err)
	}

	var existingChain *nftables.Chain
	for _, currentChain := range chains {
		if currentChain.Table.Name == chain.Table.Name && currentChain.Name == chain.Name {
			existingChain = currentChain
			break
		}
	}

	dropRule := createDropRule(chain, id)
	if existingChain != nil {
		if err := validateRegularOwnedChain(existingChain); err != nil {
			return fmt.Errorf("unsafe container-chain name collision %q: %w", chain.Name, err)
		}
		rules, err := nfc.GetRules(chain.Table, chain)
		if err != nil {
			return fmt.Errorf("error listing rules of %q chain: %w", chain.Name, err)
		}
		// An existing terminal drop is not enough: stale permissive rules before
		// it remain active while Docker/event reconciliation performs lookups and
		// policy generation. Require the canonical drop at the head so every
		// reconcile starts from quarantine and later atomically restores policy.
		if len(rules) != 0 && rulesEqual(logger, dropRule, rules[0]) {
			return nil
		}
		if !quarantineFirst && slices.ContainsFunc(rules, func(rule *nftables.Rule) bool { return rulesEqual(logger, dropRule, rule) }) {
			return nil
		}
		nfc.InsertRule(dropRule)
	} else {
		nfc.AddChain(chain)
		nfc.AddRule(dropRule)
	}

	if err := nfc.Flush(); err != nil {
		return fmt.Errorf("error installing fail-closed policy: %w", err)
	}
	return nil
}

// stripName removes the leading "/" from a container name if necessary.
func stripName(name string) string {
	if len(name) > 0 && name[0] == '/' {
		name = name[1:]
	}
	return name
}

// populateOutputRules attempts to find the IPs of containers specified
// in output rules and fills the rules appropriately.
func (r *RuleManager) populateOutputRules(ctx context.Context, tx database.TX, cfg config, id, project string, networks map[string]*network.EndpointSettings, estConts map[string]struct{}) error {
	// only get a list of containers if at least one rule specifies a
	// container
	i := slices.IndexFunc(cfg.Output, func(r ruleConfig) bool {
		return r.Container != ""
	})
	if i == -1 {
		return nil
	}
	listedConts, err := r.dockerCli.ContainerList(ctx, client.ContainerListOptions{})
	if err != nil {
		return fmt.Errorf("error listing running containers: %w", err)
	}

	containers := make(map[string]dockercontainer.InspectResponse)
	for i, ruleCfg := range cfg.Output {
		// ensure the specified network exists
		var srcNetName string
		var srcNetwork *network.EndpointSettings
		if ruleCfg.Network != "" {
			var ok bool
			srcNetName, srcNetwork, ok = findNetwork(ruleCfg.Network, project, networks)
			if !ok {
				return fmt.Errorf("output rule #%d: network %q not found",
					i,
					ruleCfg.Network,
				)
			}
		}

		if ruleCfg.Container != "" {
			ruleCfg.IdentityVersion = 1
			ruleCfg.SourceProject = project
			if srcNetwork != nil {
				ruleCfg.NetworkID = srcNetwork.NetworkID
			}
			cfg.Output[i].SourceProject = ruleCfg.SourceProject
			cfg.Output[i].NetworkID = ruleCfg.NetworkID
			cfg.Output[i].IdentityVersion = ruleCfg.IdentityVersion
			type candidate struct {
				container dockercontainer.InspectResponse
				network   *network.EndpointSettings
				netName   string
				rank      int
			}
			var candidates []candidate
			nameMatches := 0
			for _, listedCont := range listedConts {
				rank := containerNameMatchRank(ruleCfg.Container, project, listedCont.Labels, listedCont.Names...)
				if rank == 0 {
					continue
				}
				nameMatches++

				// validate container settings
				cont, ok := containers[listedCont.ID]
				if !ok {
					cont, err = r.dockerCli.ContainerInspect(ctx, listedCont.ID)
					if err != nil {
						return fmt.Errorf("error inspecting container %s: %w", listedCont.ID[:12], err)
					}
					enabled, err := whalewallEnabled(cont.Config.Labels)
					if err != nil {
						return fmt.Errorf("error parsing container %q label: %w", cont.ID[:12], err)
					}
					if !enabled {
						return fmt.Errorf("output rule #%d: container %q does not have whalewall enabled",
							i,
							ruleCfg.Container,
						)
					}
					containers[listedCont.ID] = cont
				}
				dstProject := cont.Config.Labels[composeProjectLabel]
				dstNetName, dstNetwork, ok := findNetwork(ruleCfg.Network, dstProject, cont.NetworkSettings.Networks)
				if !ok {
					continue
				}
				if !sameDockerNetwork(srcNetName, srcNetwork, dstNetName, dstNetwork) {
					continue
				}
				candidates = append(candidates, candidate{container: cont, network: dstNetwork, netName: dstNetName, rank: rank})
			}

			if len(candidates) == 0 && nameMatches != 0 {
				return fmt.Errorf("output rule #%d: container %q does not share Docker network %q with the source container", i, ruleCfg.Container, ruleCfg.Network)
			}
			if len(candidates) != 0 {
				bestRank := slices.MaxFunc(candidates, func(a, b candidate) int { return cmp.Compare(a.rank, b.rank) }).rank
				best := slices.DeleteFunc(candidates, func(c candidate) bool { return c.rank != bestRank })
				if len(best) != 1 {
					return fmt.Errorf("output rule #%d: container %q is ambiguous across %d viable containers", i, ruleCfg.Container, len(best))
				}
				selected := best[0]
				ruleCfg.ResolvedContainerID = selected.container.ID
				ruleCfg.ResolvedContainerName = stripName(selected.container.Name)
				cfg.Output[i].ResolvedContainerID = ruleCfg.ResolvedContainerID
				cfg.Output[i].ResolvedContainerName = ruleCfg.ResolvedContainerName
				exists, err := r.containerExists(ctx, tx, selected.container.ID)
				if err != nil {
					return fmt.Errorf("error querying container %s from database: %w", selected.container.ID[:12], err)
				}
				if exists {
					addr := selected.network.IPAddress
					if !addr.IsValid() || !addr.Is4() {
						return fmt.Errorf("container %q has an invalid IPv4 address on network %q", ruleCfg.Container, selected.netName)
					}
					estConts[selected.container.ID] = struct{}{}
					cfg.Output[i].IPs = []addrOrRange{{addr: addr}}
				} else {
					cfg.Output[i].skip = true
				}
			} else {
				// we need to add rules to this container's chain, but it
				// hasn't been processed yet; wait until this container
				// is processed to create the rules
				cfg.Output[i].skip = true
			}
			// Add the rule to the database so when we are processing
			// this container, this rule will be created. This is done
			// even when the container has been processed so future
			// rule creation will be idempotent.
			var buf bytes.Buffer
			encoder := gob.NewEncoder(&buf)
			if err := encoder.Encode(ruleCfg); err != nil {
				return fmt.Errorf("error encoding waiting container rule: %w", err)
			}
			err := tx.AddWaitingContainerRule(ctx, database.AddWaitingContainerRuleParams{
				SrcContainerID:   id,
				DstContainerName: ruleCfg.Container,
				Rule:             buf.Bytes(),
			})
			if err != nil {
				return fmt.Errorf("error adding waiting container rule to database: %w", err)
			}
		}
	}

	return nil
}

func sameDockerNetwork(srcName string, src *network.EndpointSettings, dstName string, dst *network.EndpointSettings) bool {
	if src == nil || dst == nil {
		return false
	}
	if src.NetworkID != "" || dst.NetworkID != "" {
		return src.NetworkID != "" && dst.NetworkID != "" && src.NetworkID == dst.NetworkID
	}
	return srcName == dstName
}

// findNetwork attempts to find a given Docker network, returning the
// name the network was found by if possible. Docker Compose sometimes
// prepends the name of the Compose project to the name the user originally
// gave the network.
func findNetwork[T any](network, project string, addrs map[string]T) (string, T, bool) {
	var zero T
	netNames := [2]string{
		network,
		project + "_" + network,
	}
	for _, netName := range netNames {
		v, ok := addrs[netName]
		if ok {
			return netName, v, true
		}
	}

	return "", zero, false
}

func containerNameMatchRank(expectedName, sourceProject string, labels map[string]string, names ...string) int {
	if len(expectedName) == 0 {
		return 0
	}

	// maybe user prefixed a backslash already?
	if slices.Contains(names, expectedName) {
		return 2
	}
	// docker prepends a backslash to container names
	slashPrefix := expectedName[0] == '/'
	if !slashPrefix && slices.Contains(names, "/"+expectedName) {
		return 2
	}
	// if the user did prefix a slash, remove it here so we hopefully
	// get a match; the service name won't be prefixed with a backslash
	if slashPrefix {
		expectedName = expectedName[1:]
	}
	// check if the Docker Compose service name matches
	if serviceName, ok := labels[composeServiceLabel]; ok && serviceName == expectedName {
		if sourceProject == "" || labels[composeProjectLabel] == sourceProject {
			return 1
		}
	}

	return 0
}

func buildChainName(_ string, id string) string {
	// Docker names are user-controlled and can exceed nftables' object-name
	// limit. A full Docker ID is only 64 bytes and avoids short-ID collisions.
	return chainPrefix + id
}

// TODO: avoid creating almost duplicate rules as output rules
// createPortMappingRules adds nftables rules to allow or deny access to
// mapped ports.
func (r *RuleManager) createPortMappingRules(nfc firewallClient, logger *zap.Logger, container dockercontainer.InspectResponse, contName string, mappedPortsCfg mappedPorts, addrs map[string][]byte, chain *nftables.Chain) ([]*nftables.Rule, error) {
	// check if there are any mapped ports to create rules for
	var hasMappedPorts bool
	for _, hostPorts := range container.NetworkSettings.Ports {
		// if an image exposes a port but no mapped ports are configured,
		// the container port it will be here with no host ports
		if len(hostPorts) != 0 {
			hasMappedPorts = true
			break
		}
	}
	if (mappedPortsCfg.Localhost.Allow || mappedPortsCfg.External.Allow) && !hasMappedPorts {
		logger.Warn("local and/or external access to mapped ports is allowed, but there are not any mapped ports")
		return nil, nil
	}
	if !hasMappedPorts {
		return nil, nil
	}

	// prepend container name and ID to log prefixes
	if mappedPortsCfg.Localhost.LogPrefix != "" {
		mappedPortsCfg.Localhost.LogPrefix = formatLogPrefix(mappedPortsCfg.Localhost.LogPrefix, contName, container.ID)
	}
	if mappedPortsCfg.External.LogPrefix != "" {
		mappedPortsCfg.External.LogPrefix = formatLogPrefix(mappedPortsCfg.External.LogPrefix, contName, container.ID)
	}

	nftRules := make([]*nftables.Rule, 0, len(container.NetworkSettings.Networks))
	for netName, netSettings := range container.NetworkSettings.Networks {
		var gateway netip.Addr
		if netSettings.Gateway.IsValid() {
			gateway = netSettings.Gateway
		} else if mappedPortsCfg.Localhost.Allow {
			logger.Warn("localhost mapped-port access cannot be enabled on a network without a gateway", zap.String("network.name", netName))
		}

		// sort mapped ports so rules are created deterministically making
		// testing much easier
		sortedPorts := slices.Collect(maps.Keys(container.NetworkSettings.Ports))
		slices.SortFunc(sortedPorts, func(a, b network.Port) int {
			if order := cmp.Compare(a.Num(), b.Num()); order != 0 {
				return order
			}
			return cmp.Compare(a.Proto(), b.Proto())
		})

		for _, port := range sortedPorts {
			hostPorts := container.NetworkSettings.Ports[port]
			localAllowed := mappedPortsCfg.Localhost.Allow

			var proto protocol
			if err := proto.UnmarshalText([]byte(port.Proto())); err != nil {
				return nil, fmt.Errorf("error parsing protocol: %w", err)
			}

			for _, hostPort := range hostPorts {
				addr := hostPort.HostIP
				if !addr.IsValid() {
					return nil, errors.New("invalid IP address in port mapping")
				}
				if addr.Is6() {
					return nil, fmt.Errorf("unsupported IPv6 published HostIP %q for port %s: Whalewall supports IPv4 bindings only", addr, hostPort.HostPort)
				}

				// TODO: make same checks for external
				if localAllowed && !addr.IsUnspecified() && addr != localAddr {
					logger.Sugar().Warnf("local access to mapped ports is allowed, but port %s is listening on %s which is not accessible to localhost",
						hostPort.HostPort,
						addr,
					)
					continue
				}
				if !localAllowed && !addr.IsUnspecified() && addr != localAddr {
					// local access is not allowed, but localhost won't
					// be able to reach this port anyway since it isn't
					// listening on 0.0.0.0 or 127.0.0.1, so no need to
					// create any rules
					continue
				}

				if gateway.IsValid() && (!localAllowed || (localAllowed && (!mappedPortsCfg.External.Allow || len(mappedPortsCfg.External.IPs) != 0))) {
					// Create rules to allow/drop traffic from container
					// network gateway to container; this will only be hit
					// for traffic originating from localhost after being
					// NATed by docker rules. If all external inbound
					// traffic is allowed, creating this is pointless as
					// the rule to allow all external inbound traffic will
					// cover traffic from the gateway too.
					rule := ruleDetails{
						inbound: true,
						addr:    addrs[netName],
						cfg: ruleConfig{
							LogPrefix: mappedPortsCfg.Localhost.LogPrefix,
							IPs: []addrOrRange{
								{addr: gateway},
							},
							Proto: proto,
							DstPorts: []rulePorts{
								{
									single: port.Num(),
								},
							},
							Verdict: mappedPortsCfg.Localhost.Verdict,
						},
						chain:  chain,
						contID: container.ID,
					}
					rule.cfg.Verdict.drop = !localAllowed

					rules, err := createNFTRules(nfc, logger, rule)
					if err != nil {
						return nil, fmt.Errorf("error creating firewall rules: %w", err)
					}
					nftRules = append(nftRules, rules...)
				}

				if !localAllowed {
					// Create rule to drop traffic going to the mapped
					// host port. This will prevent traffic originating
					// from localhost to be seen by Docker at all.
					hostPortInt, err := strconv.ParseUint(hostPort.HostPort, 10, 16)
					if err != nil {
						return nil, fmt.Errorf("error parsing host port of port mapping: %w", err)
					}

					localhostDropRule := ruleDetails{
						inbound: true,
						cfg: ruleConfig{
							IPs: []addrOrRange{
								{addr: localAddr},
							},
							Proto: proto,
							DstPorts: []rulePorts{
								{
									single: uint16(hostPortInt),
								},
							},
							Verdict: verdict{
								drop: true,
							},
						},
						chain:  whalewallChain,
						contID: container.ID,
					}

					rules, err := createNFTRules(nfc, logger, localhostDropRule)
					if err != nil {
						return nil, fmt.Errorf("error creating firewall rules: %w", err)
					}
					nftRules = append(nftRules, rules...)
				}
			}

			// if there are no host ports mapped to the container port,
			// don't create allow rules as the port wasn't exposed by
			// the user but rather was created from an EXPOSE Dockerfile
			// directive
			if mappedPortsCfg.External.Allow && len(hostPorts) > 0 {
				// create rules to allow external traffic to container
				rule := ruleDetails{
					inbound: true,
					addr:    addrs[netName],
					cfg: ruleConfig{
						LogPrefix: mappedPortsCfg.External.LogPrefix,
						IPs:       mappedPortsCfg.External.IPs,
						Proto:     proto,
						DstPorts: []rulePorts{
							{
								single: port.Num(),
							},
						},
						Verdict: mappedPortsCfg.External.Verdict,
					},
					chain:  chain,
					contID: container.ID,
				}

				rules, err := createNFTRules(nfc, logger, rule)
				if err != nil {
					return nil, fmt.Errorf("error creating firewall rules: %w", err)
				}
				nftRules = append(nftRules, rules...)
			}
		}
	}

	return nftRules, nil
}

// createOutputRules adds nftables rules to allow outbound access from
// a container.
func (r *RuleManager) createOutputRules(ctx context.Context, nfc firewallClient, logger *zap.Logger, tx database.TX, ruleCfgs []ruleConfig, project string, addrs map[string][]byte, chain *nftables.Chain, name, id string) ([]*nftables.Rule, error) {
	nftRules := make([]*nftables.Rule, 0, len(ruleCfgs)*3)
	for _, ruleCfg := range ruleCfgs {
		// prepend container name and ID to log prefixes
		if ruleCfg.LogPrefix != "" {
			ruleCfg.LogPrefix = formatLogPrefix(ruleCfg.LogPrefix, name, id)
		}

		rule := ruleDetails{
			inbound: false,
			cfg:     ruleCfg,
			chain:   chain,
			contID:  id,
		}

		if ruleCfg.Network != "" {
			_, addr, ok := findNetwork(ruleCfg.Network, project, addrs)
			if !ok {
				return nil, fmt.Errorf("network %q not found", ruleCfg.Network)
			}
			rule.addr = addr

			if ruleCfg.Container != "" {
				if ruleCfg.skip {
					// the container either hasn't been started yet or
					// doesn't exist; this rule will be created when
					// processing this container later
					continue
				}

				dstID, dstName := ruleCfg.ResolvedContainerID, ruleCfg.ResolvedContainerName
				if dstID == "" || dstName == "" {
					// Legacy waiting rows may not carry resolved identity. New policy
					// generation always does; retain a compatibility fallback so a
					// first-deploy clear can be performed cleanly.
					var err error
					dstID, dstName, err = r.getContainerIDAndName(ctx, tx, ruleCfg.Container)
					if err != nil {
						return nil, fmt.Errorf("error getting container %q ID from database: %w", ruleCfg.Container, err)
					}
				}
				rule.estChain = &nftables.Chain{
					Table: filterTable,
					Name:  buildChainName(dstName, dstID),
				}
				rule.contID = dstID
				rule.estContID = id
			}

			rules, err := createNFTRules(nfc, logger, rule)
			if err != nil {
				return nil, fmt.Errorf("error creating firewall rules: %w", err)
			}
			nftRules = append(nftRules, rules...)
		} else {
			for _, addr := range addrs {
				rule.addr = addr
				rules, err := createNFTRules(nfc, logger, rule)
				if err != nil {
					return nil, fmt.Errorf("error creating firewall rules: %w", err)
				}
				nftRules = append(nftRules, rules...)
			}
		}
	}

	return nftRules, nil
}

// getContainerIDAndName returns the ID and canonical name of a container
// if it is present in the database.
func (r *RuleManager) getContainerIDAndName(ctx context.Context, db database.Querier, contName string) (string, string, error) {
	name := contName

	id, err := db.GetContainerID(ctx, contName)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return "", "", fmt.Errorf("error getting container %q ID from database: %w", contName, err)
		}

		info, err := db.GetContainerIDAndNameFromAlias(ctx, contName)
		if err != nil {
			return "", "", fmt.Errorf("error getting container %q ID from database: %w", contName, err)
		}

		id = info.ID
		name = info.Name
	}

	return id, name, nil
}

// createWaitingContainerRules creates nftables rules to allow access
// from another container to this container. The other container was
// processed before this container, so rules concerning this container
// couldn't be created until now.
func (r *RuleManager) createWaitingContainerRules(ctx context.Context, nfc firewallClient, logger *zap.Logger, tx database.TX, id, name, service, project string, networks map[string]*network.EndpointSettings, chain *nftables.Chain, estContainers map[string]struct{}) ([]*nftables.Rule, error) {
	var (
		waitingRules []database.GetWaitingContainerRulesRow
		err          error
		aliases      = append([]string{name}, containerAliases(name, service)...)
	)

	seenWaiting := make(map[string]struct{})
	for _, alias := range aliases {
		rows, queryErr := tx.GetWaitingContainerRules(ctx, alias)
		err = queryErr
		if err != nil {
			return nil, fmt.Errorf("error getting waiting container rules of %q from database: %w", alias, err)
		}
		for _, row := range rows {
			key := row.SrcContainerID + "\x00" + string(row.Rule)
			if _, ok := seenWaiting[key]; ok {
				continue
			}
			seenWaiting[key] = struct{}{}
			waitingRules = append(waitingRules, row)
		}
	}
	if len(waitingRules) == 0 {
		return nil, nil
	}

	nftRules := make([]*nftables.Rule, 0, len(waitingRules)*3)
	for _, waitingRule := range waitingRules {
		decoder := gob.NewDecoder(bytes.NewReader(waitingRule.Rule))
		var ruleCfg ruleConfig
		if err := decoder.Decode(&ruleCfg); err != nil {
			return nil, fmt.Errorf("error decoding waiting container rule: %w", err)
		}
		if err := validateRule(ruleCfg); err != nil {
			return nil, fmt.Errorf("invalid waiting container rule from %q: %w", waitingRule.Name, err)
		}
		if ruleCfg.IdentityVersion == 0 && ruleCfg.ResolvedContainerID == "" && ruleCfg.SourceProject == "" && ruleCfg.NetworkID == "" {
			// Baseline gob rows had no project/network/container identity. Applying
			// one by a shared service alias can grant access to another Compose
			// project. Skip fail-closed; the source's periodic rebuild replaces it.
			logger.Warn("skipping legacy waiting rule without hardened destination identity",
				zap.String("source.container.id", waitingRule.SrcContainerID),
				zap.String("destination.alias", ruleCfg.Container))
			continue
		}
		exactDestination := ruleCfg.ResolvedContainerID != ""
		if exactDestination && ruleCfg.ResolvedContainerID != id {
			continue
		}
		if !exactDestination && ruleCfg.SourceProject != "" && project != ruleCfg.SourceProject {
			// Same service alias in another Compose project.
			continue
		}

		// Resolve this destination first so unrelated legacy/service rows can be
		// filtered by canonical network identity without quarantining it.
		dstNetName, dstNetwork, ok := findNetwork(ruleCfg.Network, project, networks)
		if !ok {
			if exactDestination {
				return nil, fmt.Errorf("network %q not found", ruleCfg.Network)
			}
			continue
		}
		if ruleCfg.NetworkID != "" && dstNetwork.NetworkID != "" && ruleCfg.NetworkID != dstNetwork.NetworkID {
			if exactDestination {
				return nil, fmt.Errorf("destination container %q moved to a different Docker network", name)
			}
			continue
		}

		// find source container IP (not this container)
		srcCont, err := r.dockerCli.ContainerInspect(ctx, waitingRule.SrcContainerID)
		if err != nil {
			return nil, fmt.Errorf("error inspecting container %q: %w", waitingRule.Name, err)
		}
		enabled, err := whalewallEnabled(srcCont.Config.Labels)
		if err != nil || !enabled {
			return nil, fmt.Errorf("source container %q no longer has a valid enabled Whalewall policy", waitingRule.Name)
		}
		srcProject := srcCont.Config.Labels[composeProjectLabel]
		srcNetName, srcNetwork, ok := findNetwork(ruleCfg.Network, srcProject, srcCont.NetworkSettings.Networks)
		if !ok {
			return nil, fmt.Errorf("network %q not found for container %q",
				ruleCfg.Network,
				ruleCfg.Container,
			)
		}
		srcAddr := srcNetwork.IPAddress
		if !srcAddr.IsValid() || !srcAddr.Is4() {
			return nil, fmt.Errorf("container %q has an invalid IPv4 address on network %q", ruleCfg.Container, srcNetName)
		}

		if !sameDockerNetwork(srcNetName, srcNetwork, dstNetName, dstNetwork) {
			if exactDestination {
				return nil, fmt.Errorf("source container %q and destination container %q do not share Docker network %q", waitingRule.Name, name, ruleCfg.Network)
			}
			continue
		}
		dstAddr := dstNetwork.IPAddress
		if !dstAddr.IsValid() || !dstAddr.Is4() {
			return nil, fmt.Errorf("invalid IPv4 address on network %q", dstNetName)
		}
		ruleCfg.IPs = []addrOrRange{{addr: dstAddr}}

		// create rules
		rule := ruleDetails{
			inbound: false,
			addr:    ref(srcAddr.As4())[:],
			cfg:     ruleCfg,
			chain: &nftables.Chain{
				Table: filterTable,
				Name:  buildChainName(waitingRule.Name, waitingRule.SrcContainerID),
			},
			estChain:  chain,
			contID:    id,
			estContID: waitingRule.SrcContainerID,
		}

		rules, err := createNFTRules(nfc, logger, rule)
		if err != nil {
			return nil, fmt.Errorf("error creating firewall rules: %w", err)
		}
		nftRules = append(nftRules, rules...)
		estContainers[waitingRule.SrcContainerID] = struct{}{}
	}

	return nftRules, nil
}

func formatLogPrefix(prefix, name, id string) string {
	prefix = fmt.Sprintf("whalewall-%s-%s %s", name, id[:12], prefix)
	if !strings.HasSuffix(prefix, ": ") {
		prefix += ": "
	}
	return boundLogPrefix(prefix)
}

func boundLogPrefix(prefix string) string {
	if len(prefix) > maxLogPrefixBytes {
		prefix = prefix[:maxLogPrefixBytes]
		for !utf8.ValidString(prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}

	return prefix
}

type ruleDetails struct {
	inbound   bool
	addr      []byte
	cfg       ruleConfig
	chain     *nftables.Chain
	estChain  *nftables.Chain
	contID    string
	estContID string
}

func (r ruleDetails) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddBool("inbound", r.inbound)
	if len(r.addr) != 0 {
		ip, ok := netip.AddrFromSlice(r.addr)
		if !ok {
			return fmt.Errorf("error parsing addr %v", r.addr)
		}
		enc.AddString("container_addr", ip.String())
	}
	zap.Inline(r.cfg).AddTo(enc)
	if r.chain != nil {
		enc.AddString("chain", r.chain.Name)
	}
	if r.estChain != nil {
		enc.AddString("est_chain", r.estChain.Name)
	}
	enc.AddString("cont_id", r.contID[:12])
	if r.estContID != "" {
		enc.AddString("est_cont_id", r.estContID[:12])
	}

	return nil
}

// createNFTRules returns a slice of [*nftables.Rule] described by rd.
func createNFTRules(nfc firewallClient, logger *zap.Logger, rd ruleDetails) ([]*nftables.Rule, error) {
	logger.Debug("generating rule", zap.Object("rule", rd))

	rules := make([]*nftables.Rule, 0, 3)
	estContID := rd.contID
	if rd.estChain == nil {
		rd.estChain = rd.chain
	} else {
		estContID = rd.estContID
	}

	// if the rule is a drop rule, only need to handle new traffic
	if rd.cfg.Verdict.drop {
		rule, err := createNFTRule(nfc, rd.inbound, false, stateNew, rd.addr, rd.cfg, 0, rd.chain, rd.contID)
		if err != nil {
			return nil, err
		}
		return append(rules, rule), nil
	}

	if rd.cfg.Verdict.Queue == 0 {
		if rd.cfg.LogPrefix == "" {
			newEstRule, err := createNFTRule(nfc, rd.inbound, false, stateNewEst, rd.addr, rd.cfg, 0, rd.chain, rd.contID)
			if err != nil {
				return nil, err
			}
			estRule, err := createNFTRule(nfc, !rd.inbound, true, stateEst, rd.addr, rd.cfg, 0, rd.estChain, estContID)
			if err != nil {
				return nil, err
			}
			return append(rules, newEstRule, estRule), nil
		}

		// create a separate rule for new traffic to log it
		dstNewRule, err := createNFTRule(nfc, rd.inbound, false, stateNew, rd.addr, rd.cfg, 0, rd.chain, rd.contID)
		if err != nil {
			return nil, err
		}
		dstEstRule, err := createNFTRule(nfc, rd.inbound, false, stateEst, rd.addr, rd.cfg, 0, rd.chain, rd.contID)
		if err != nil {
			return nil, err
		}
		srcEstRule, err := createNFTRule(nfc, !rd.inbound, true, stateEst, rd.addr, rd.cfg, 0, rd.estChain, estContID)
		if err != nil {
			return nil, err
		}
		return append(rules, dstNewRule, dstEstRule, srcEstRule), nil
	}

	// If there is no log prefix set we can create one inbound rule and
	// one outbound rule in some situations. Otherwise new traffic must
	// be logged.
	if rd.cfg.LogPrefix == "" {
		if rd.inbound && rd.cfg.Verdict.Queue == rd.cfg.Verdict.InputEstQueue {
			// if rule is inbound and queue and established inbound queue
			// are the same, create one rule for inbound traffic
			newEstRule, err := createNFTRule(nfc, true, false, stateNewEst, rd.addr, rd.cfg, rd.cfg.Verdict.Queue, rd.chain, rd.contID)
			if err != nil {
				return nil, err
			}
			estRule, err := createNFTRule(nfc, false, true, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.OutputEstQueue, rd.estChain, estContID)
			if err != nil {
				return nil, err
			}
			return append(rules, newEstRule, estRule), nil
		} else if !rd.inbound && rd.cfg.Verdict.Queue == rd.cfg.Verdict.OutputEstQueue {
			// if rule is outbound and queue and established outbound queue
			// are the same, create one rule for outbound traffic
			newEstRule, err := createNFTRule(nfc, false, false, stateNewEst, rd.addr, rd.cfg, rd.cfg.Verdict.Queue, rd.chain, rd.contID)
			if err != nil {
				return nil, err
			}
			estRule, err := createNFTRule(nfc, true, true, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.InputEstQueue, rd.estChain, estContID)
			if err != nil {
				return nil, err
			}
			return append(rules, newEstRule, estRule), nil
		}
	}

	// if rule is inbound and queue and established inbound queue
	// are different, need to create separate rules for them;
	// or, logging was requested which means we need to create a
	// separate rule for new traffic
	if rd.inbound {
		dstNewRule, err := createNFTRule(nfc, true, false, stateNew, rd.addr, rd.cfg, rd.cfg.Verdict.Queue, rd.chain, rd.contID)
		if err != nil {
			return nil, err
		}
		dstEstRule, err := createNFTRule(nfc, true, false, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.InputEstQueue, rd.chain, rd.contID)
		if err != nil {
			return nil, err
		}
		srcEstRule, err := createNFTRule(nfc, false, true, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.OutputEstQueue, rd.estChain, estContID)
		if err != nil {
			return nil, err
		}
		return append(rules, dstNewRule, dstEstRule, srcEstRule), nil
	}

	// if rule is outbound and queue and established outbound queue
	// are different, need to create separate rules for them;
	// or, logging was requested which means we need to create a
	// separate rule for new traffic
	dstNewRule, err := createNFTRule(nfc, false, false, stateNew, rd.addr, rd.cfg, rd.cfg.Verdict.Queue, rd.chain, rd.contID)
	if err != nil {
		return nil, err
	}
	dstEstRule, err := createNFTRule(nfc, false, false, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.OutputEstQueue, rd.chain, rd.contID)
	if err != nil {
		return nil, err
	}
	srcEstRule, err := createNFTRule(nfc, true, true, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.InputEstQueue, rd.estChain, estContID)
	if err != nil {
		return nil, err
	}
	return append(rules, dstNewRule, dstEstRule, srcEstRule), nil
}

func createNFTRule(nfc firewallClient, inbound, inversePortOffsets bool, state uint32, addr []byte, cfg ruleConfig, queueNum uint16, chain *nftables.Chain, contID string) (*nftables.Rule, error) {
	addrOffset := srcAddrOffset
	cfgAddrOffset := dstAddrOffset
	if inbound {
		addrOffset = dstAddrOffset
		cfgAddrOffset = srcAddrOffset
	}
	proto := unix.IPPROTO_TCP
	if cfg.Proto == udp {
		proto = unix.IPPROTO_UDP
	}
	exprs := make([]expr.Any, 0, 15)
	if len(cfg.IPs) != 0 {
		var addrExprs []expr.Any
		if len(addr) != 0 {
			addrExprs = matchAddrExprs(addr, addrOffset)
		}
		cfgAddrExprs, err := createIPExprs(nfc, cfg.IPs, cfgAddrOffset, chain)
		if err != nil {
			return nil, err
		}
		if inbound {
			exprs = append(exprs, cfgAddrExprs...)
			exprs = append(exprs, addrExprs...)
		} else {
			exprs = append(exprs, addrExprs...)
			exprs = append(exprs, cfgAddrExprs...)
		}
	} else if len(addr) != 0 {
		exprs = append(exprs, matchAddrExprs(addr, addrOffset)...)
	}

	if cfg.Proto != invalidProto {
		exprs = append(exprs, matchProtoExprs(proto)...)
	}

	var srcPortExprs []expr.Any
	var dstPortExprs []expr.Any
	if len(cfg.SrcPorts) != 0 {
		portOffset := srcPortOffset
		if inversePortOffsets {
			portOffset = dstPortOffset
		}
		portExprs, err := createPortExprs(nfc, cfg.SrcPorts, portOffset, chain)
		if err != nil {
			return nil, err
		}
		srcPortExprs = portExprs
	}
	if len(cfg.DstPorts) != 0 {
		portOffset := dstPortOffset
		if inversePortOffsets {
			portOffset = srcPortOffset
		}
		portExprs, err := createPortExprs(nfc, cfg.DstPorts, portOffset, chain)
		if err != nil {
			return nil, err
		}
		dstPortExprs = portExprs
	}
	if !inversePortOffsets {
		exprs = append(exprs, srcPortExprs...)
		exprs = append(exprs, dstPortExprs...)
	} else {
		exprs = append(exprs, dstPortExprs...)
		exprs = append(exprs, srcPortExprs...)
	}

	exprs = append(exprs, matchConnStateExprs(state)...)
	exprs = append(exprs, &expr.Counter{})
	if state == stateNew && cfg.LogPrefix != "" {
		exprs = append(exprs, logExpr(cfg.LogPrefix))
	}

	switch {
	case cfg.Verdict.Chain != "":
		exprs = append(exprs,
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: cfg.Verdict.Chain,
			},
		)
	case queueNum != 0:
		exprs = append(exprs,
			&expr.Queue{
				Num: queueNum,
			},
		)
	case cfg.Verdict.drop:
		exprs = append(exprs, dropVerdict)
	default:
		exprs = append(exprs, allowReturnVerdict)
	}

	return &nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		Exprs:    exprs,
		UserData: []byte(contID),
	}, nil
}

func createIPExprs(nfc firewallClient, addrs []addrOrRange, addrOffset uint32, chain *nftables.Chain) ([]expr.Any, error) {
	var exprs []expr.Any

	if len(addrs) == 1 {
		if addr, ok := addrs[0].Addr(); ok {
			exprs = matchAddrExprs(ref(addr.As4())[:], addrOffset)
		} else if lowAddr, highAddr, ok := addrs[0].Range(); ok {
			exprs = matchAddrRangeExprs(lowAddr, highAddr, addrOffset)
		} else {
			// should never happen if cfg.IP.IsValid is true
			return nil, errors.New("whalewall bug: invalid IP address")
		}
		return exprs, nil
	}

	elements := make([]nftables.SetElement, 0, len(addrs)*2)
	hasInterval := slices.ContainsFunc(addrs, func(a addrOrRange) bool { _, _, ok := a.Range(); return ok })
	if !hasInterval {
		unique := make(map[uint32]struct{}, len(addrs))
		for _, configured := range addrs {
			addr, ok := configured.Addr()
			if !ok {
				return nil, errors.New("whalewall bug: invalid IP address")
			}
			unique[binary.BigEndian.Uint32(ref(addr.As4())[:])] = struct{}{}
		}
		values := slices.Collect(maps.Keys(unique))
		slices.Sort(values)
		for _, value := range values {
			elements = append(elements, nftables.SetElement{Key: binary.BigEndian.AppendUint32(nil, value)})
		}
	} else {
		intervals := make([]uint32Interval, 0, len(addrs))
		for _, configured := range addrs {
			if addr, ok := configured.Addr(); ok {
				value := binary.BigEndian.Uint32(ref(addr.As4())[:])
				intervals = append(intervals, uint32Interval{low: value, high: value})
				continue
			}
			if low, high, ok := configured.Range(); ok {
				intervals = append(intervals, uint32Interval{
					low: binary.BigEndian.Uint32(ref(low.As4())[:]), high: binary.BigEndian.Uint32(ref(high.As4())[:]),
				})
				continue
			}
			return nil, errors.New("whalewall bug: invalid IP address")
		}
		for _, interval := range mergeUint32Intervals(intervals) {
			elements = append(elements, nftables.SetElement{Key: binary.BigEndian.AppendUint32(nil, interval.low)})
			if interval.high != ^uint32(0) {
				elements = append(elements, nftables.SetElement{Key: binary.BigEndian.AppendUint32(nil, interval.high+1), IntervalEnd: true})
			}
		}
	}
	set := &nftables.Set{
		Table: chain.Table, Anonymous: true, Constant: true,
		Interval: hasInterval, KeyType: nftables.TypeIPAddr,
	}
	if err := nfc.AddSet(set, elements); err != nil {
		return nil, fmt.Errorf("error creating address union set: %w", err)
	}
	return []expr.Any{getAddrExpr(addrOffset), matchFromSetExpr(set)}, nil
}

func createPortExprs(nfc firewallClient, ports []rulePorts, portOffset uint32, chain *nftables.Chain) ([]expr.Any, error) {
	var exprs []expr.Any

	if len(ports) == 1 {
		if ports[0].single != 0 {
			exprs = matchPortExprs(ports[0].single, portOffset)
		} else {
			exprs = matchPortsExprs(ports[0].interval, portOffset)
		}
		return exprs, nil
	}

	elements := make([]nftables.SetElement, 0, len(ports)*2)
	hasInterval := slices.ContainsFunc(ports, func(p rulePorts) bool { return p.single == 0 })
	if !hasInterval {
		unique := make(map[uint16]struct{}, len(ports))
		for _, port := range ports {
			unique[port.single] = struct{}{}
		}
		values := slices.Collect(maps.Keys(unique))
		slices.Sort(values)
		for _, value := range values {
			elements = append(elements, nftables.SetElement{Key: binary.BigEndian.AppendUint16(nil, value)})
		}
	} else {
		intervals := make([]uint16Interval, 0, len(ports))
		for _, port := range ports {
			if port.single != 0 {
				intervals = append(intervals, uint16Interval{low: port.single, high: port.single})
			} else {
				intervals = append(intervals, uint16Interval{low: port.interval.min, high: port.interval.max})
			}
		}
		for _, interval := range mergeUint16Intervals(intervals) {
			elements = append(elements, nftables.SetElement{Key: binary.BigEndian.AppendUint16(nil, interval.low)})
			if interval.high != ^uint16(0) {
				elements = append(elements, nftables.SetElement{Key: binary.BigEndian.AppendUint16(nil, interval.high+1), IntervalEnd: true})
			}
		}
	}
	set := &nftables.Set{
		Table: chain.Table, Anonymous: true, Constant: true,
		Interval: hasInterval, KeyType: nftables.TypeInetService,
	}
	if err := nfc.AddSet(set, elements); err != nil {
		return nil, fmt.Errorf("error creating port union set: %w", err)
	}
	return []expr.Any{getPortExpr(portOffset), matchFromSetExpr(set)}, nil
}

type uint32Interval struct{ low, high uint32 }

func mergeUint32Intervals(intervals []uint32Interval) []uint32Interval {
	slices.SortFunc(intervals, func(a, b uint32Interval) int {
		if order := cmp.Compare(a.low, b.low); order != 0 {
			return order
		}
		return cmp.Compare(a.high, b.high)
	})
	merged := make([]uint32Interval, 0, len(intervals))
	for _, interval := range intervals {
		if len(merged) == 0 {
			merged = append(merged, interval)
			continue
		}
		last := &merged[len(merged)-1]
		if interval.low <= last.high || (last.high != ^uint32(0) && interval.low == last.high+1) {
			last.high = max(last.high, interval.high)
			continue
		}
		merged = append(merged, interval)
	}
	return merged
}

type uint16Interval struct{ low, high uint16 }

func mergeUint16Intervals(intervals []uint16Interval) []uint16Interval {
	slices.SortFunc(intervals, func(a, b uint16Interval) int {
		if order := cmp.Compare(a.low, b.low); order != 0 {
			return order
		}
		return cmp.Compare(a.high, b.high)
	})
	merged := make([]uint16Interval, 0, len(intervals))
	for _, interval := range intervals {
		if len(merged) == 0 {
			merged = append(merged, interval)
			continue
		}
		last := &merged[len(merged)-1]
		if interval.low <= last.high || (last.high != ^uint16(0) && interval.low == last.high+1) {
			last.high = max(last.high, interval.high)
			continue
		}
		merged = append(merged, interval)
	}
	return merged
}

func matchAddrExprs(addr []byte, offset uint32) []expr.Any {
	return []expr.Any{
		getAddrExpr(offset),
		compareAddrExpr(addr),
	}
}

func getAddrExpr(offset uint32) expr.Any {
	// [ payload load 4b @ network header + ... => reg 1 ]
	return &expr.Payload{
		OperationType: expr.PayloadLoad,
		Len:           4,
		Base:          expr.PayloadBaseNetworkHeader,
		Offset:        offset,
		DestRegister:  1,
	}
}

func compareAddrExpr(addr []byte) expr.Any {
	// [ cmp eq reg 1 ... ]
	return &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     addr,
	}
}

func matchAddrRangeExprs(lowAddr, highAddr netip.Addr, offset uint32) []expr.Any {
	exprs := make([]expr.Any, 0, 3)
	exprs = append(exprs, getAddrExpr(offset))
	return append(exprs, compareAddrRangeExprs(ref(lowAddr.As4())[:], ref(highAddr.As4())[:])...)
}

func compareAddrRangeExprs(lowAddr, highAddr []byte) []expr.Any {
	return []expr.Any{
		// [ cmp gte reg 1 ... ]
		&expr.Cmp{
			Op:       expr.CmpOpGte,
			Register: 1,
			Data:     lowAddr,
		},
		// [ cmp lte reg 1 ... ]
		&expr.Cmp{
			Op:       expr.CmpOpLte,
			Register: 1,
			Data:     highAddr,
		},
	}
}

func matchProtoExprs(proto int) []expr.Any {
	return []expr.Any{
		// [ meta load l4proto => reg 1 ]
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		},
		// [ cmp eq reg 1 ... ]
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{byte(proto)},
		},
	}
}

func matchPortExprs(port uint16, offset uint32) []expr.Any {
	return []expr.Any{
		getPortExpr(offset),
		comparePortExpr(port),
	}
}

func getPortExpr(offset uint32) expr.Any {
	// [ payload load 2b @ transport header + ... => reg 1 ]
	return &expr.Payload{
		OperationType: expr.PayloadLoad,
		Len:           2,
		Base:          expr.PayloadBaseTransportHeader,
		Offset:        offset,
		DestRegister:  1,
	}
}

func comparePortExpr(port uint16) expr.Any {
	// [ cmp eq reg 1 ... ]
	return &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     binary.BigEndian.AppendUint16(nil, port),
	}
}

func matchPortsExprs(ports portInterval, offset uint32) []expr.Any {
	exprs := make([]expr.Any, 0, 3)
	exprs = append(exprs, getPortExpr(offset))
	exprs = append(exprs, comparePortsExprs(ports)...)
	return exprs
}

func comparePortsExprs(ports portInterval) []expr.Any {
	return []expr.Any{
		// [ cmp gte reg 1 ... ]
		&expr.Cmp{
			Op:       expr.CmpOpGte,
			Register: 1,
			Data:     binary.BigEndian.AppendUint16(nil, ports.min),
		},
		// [ cmp lte reg 1 ... ]
		&expr.Cmp{
			Op:       expr.CmpOpLte,
			Register: 1,
			Data:     binary.BigEndian.AppendUint16(nil, ports.max),
		},
	}
}

func matchFromSetExpr(set *nftables.Set) expr.Any {
	// [ lookup reg 1 set ... 0x0 ]
	return &expr.Lookup{
		SourceRegister: 1,
		SetID:          set.ID,
		SetName:        set.Name,
	}
}

func matchConnStateExprs(state uint32) []expr.Any {
	return []expr.Any{
		// [ ct load state => reg 1 ]
		&expr.Ct{
			Key:      expr.CtKeySTATE,
			Register: 1,
		},
		// [ bitwise reg 1 = ( reg 1 & ... ) ^ 0x00000000 ]
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binary.LittleEndian.AppendUint32(nil, state),
			Xor:            zeroUint32,
		},
		// [ cmp neq reg 1 0x00000000 ]
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     zeroUint32,
		},
	}
}

func logExpr(prefix string) expr.Any {
	return &expr.Log{
		Key:   (1 << unix.NFTA_LOG_PREFIX) | (1 << unix.NFTA_LOG_LEVEL),
		Level: expr.LogLevelInfo,
		Data:  []byte(boundLogPrefix(prefix)),
	}
}

func createDropRule(chain *nftables.Chain, id string) *nftables.Rule {
	return &nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Counter{},
			logExpr(chain.Name + " drop: "),
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
		UserData: []byte(id),
	}
}

func ref[T any](v T) *T {
	return &v
}
