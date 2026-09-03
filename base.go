package whalewall

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go.uber.org/zap"
)

const (
	filterTableName      = "filter"
	dockerChainName      = "DOCKER-USER"
	forwardChainName     = "FORWARD"
	inputChainName       = "INPUT"
	outputChainName      = "OUTPUT"
	whalewallChainName   = "whalewall"
	containerAddrSetName = "whalewall-container-addrs"
	bridgeNfCallIptables = "/proc/sys/net/bridge/bridge-nf-call-iptables"
)

// ValidateRuntimePrerequisites verifies the host setting required for bridged
// IPv4 packets to traverse the iptables-nft hooks used by Whalewall. It must be
// called before applying Landlock, which intentionally prevents later reads
// from /proc.
func ValidateRuntimePrerequisites() error {
	return validateBridgeNetfilter(os.ReadFile)
}

func validateBridgeNetfilter(readFile func(string) ([]byte, error)) error {
	value, err := readFile(bridgeNfCallIptables)
	if err != nil {
		return fmt.Errorf("cannot verify br_netfilter prerequisite %q: %w", bridgeNfCallIptables, err)
	}
	if strings.TrimSpace(string(value)) != "1" {
		return fmt.Errorf("unsupported bridge firewall configuration: %s must be 1 (Whalewall supports IPv4 with Docker firewall-backend=iptables backed by nftables only)", bridgeNfCallIptables)
	}
	return nil
}

var (
	filterTable = &nftables.Table{
		Name:   filterTableName,
		Family: nftables.TableFamilyIPv4,
	}
	whalewallChain = &nftables.Chain{
		Name:  whalewallChainName,
		Table: filterTable,
		Type:  nftables.ChainTypeFilter,
	}
	srcJumpRule = &nftables.Rule{
		Table: filterTable,
		Chain: whalewallChain,
		Exprs: []expr.Any{
			// [ payload load 4b @ network header + 12 => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        12,
				DestRegister:  1,
			},
			// [ lookup reg 1 set ... dreg 0 0x0 ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        containerAddrSetName,
				DestRegister:   0,
				IsDestRegSet:   true,
			},
		},
	}
	dstJumpRule = &nftables.Rule{
		Table: filterTable,
		Chain: whalewallChain,
		Exprs: []expr.Any{
			// [ payload load 4b @ network header + 16 => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        16,
				DestRegister:  1,
			},
			// [ lookup reg 1 set ... dreg 0 0x0 ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        containerAddrSetName,
				DestRegister:   0,
				IsDestRegSet:   true,
			},
		},
	}
)

func (r *RuleManager) createBaseRules() error {
	r.addressMapMu.Lock()
	defer r.addressMapMu.Unlock()

	nfc, err := r.newFirewallClient()
	if err != nil {
		return fmt.Errorf("error creating netlink connection: %w", err)
	}

	chains, err := nfc.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("error listing IPv4 chains: %w", err)
	}
	var (
		existingWhalewallChain *nftables.Chain
		dockerChain            *nftables.Chain
		forwardChain           *nftables.Chain
		inputChain             *nftables.Chain
		outputChain            *nftables.Chain
	)
	for _, c := range chains {
		if c.Table.Name != filterTableName {
			continue
		}

		switch c.Name {
		case dockerChainName:
			dockerChain = c
		case forwardChainName:
			forwardChain = c
		case whalewallChainName:
			existingWhalewallChain = c
		case inputChainName:
			inputChain = c
		case outputChainName:
			outputChain = c
		}
	}
	if dockerChain == nil {
		return errors.New("required nftables chain ip filter DOCKER-USER was not found; Whalewall supports IPv4 with Docker firewall-backend=iptables backed by nftables only (not iptables-legacy or Docker's native nftables backend)")
	}
	if err := validateRegularOwnedChain(dockerChain); err != nil {
		return fmt.Errorf("invalid Docker chain %q: %w", dockerChainName, err)
	}
	if forwardChain == nil {
		return errors.New("required nftables chain ip filter FORWARD was not found")
	}
	if err := validateBaseChain(forwardChain, nftables.ChainHookForward); err != nil {
		return fmt.Errorf("invalid Docker FORWARD base chain: %w", err)
	}
	forwardRules, err := nfc.GetRules(filterTable, forwardChain)
	if err != nil {
		return fmt.Errorf("error listing rules of %q chain: %w", forwardChainName, err)
	}
	if len(forwardRules) == 0 || !isUnconditionalJump(forwardRules[0], dockerChainName) {
		return errors.New("ip filter FORWARD does not begin with an unconditional jump to DOCKER-USER; Docker iptables-nft integration is not active")
	}
	if inputChain != nil {
		if err := validateBaseChain(inputChain, nftables.ChainHookInput); err != nil {
			return fmt.Errorf("invalid INPUT base chain: %w", err)
		}
	}
	if outputChain != nil {
		if err := validateBaseChain(outputChain, nftables.ChainHookOutput); err != nil {
			return fmt.Errorf("invalid OUTPUT base chain: %w", err)
		}
	}

	// Inspect the verdict map before queuing any repair. A released legacy
	// installation used absolute JUMP mappings and name-based chains; silently
	// repairing around those entries could mix incompatible policy models.
	// Operators must clear the old version first while workloads are stopped.
	desiredSet := containerAddressSet()
	existingSet, err := nfc.GetSetByName(filterTable, containerAddrSetName)
	setMissing := errors.Is(err, syscall.ENOENT)
	if err != nil && !setMissing {
		return fmt.Errorf("error inspecting set %q: %w", containerAddrSetName, err)
	}
	if !setMissing {
		if !containerAddressSetSchemaEqual(existingSet, desiredSet) {
			return fmt.Errorf("existing set %q has an incompatible schema", containerAddrSetName)
		}
		elements, err := nfc.GetSetElements(existingSet)
		if err != nil {
			return fmt.Errorf("error inspecting set %q elements: %w", containerAddrSetName, err)
		}
		for _, element := range elements {
			if _, err := containerMappingVerdict(element); err != nil {
				return fmt.Errorf("existing set %q contains an incompatible mapping for key %x (clear the old Whalewall version before upgrading): %w", containerAddrSetName, element.Key, err)
			}
		}
	}

	// Get or create the Whalewall chain. All repair operations below are
	// queued on this connection and committed by one final Flush, so a missing
	// base component can never expose a partially wired dispatcher.
	var mainChainRules []*nftables.Rule
	if existingWhalewallChain == nil {
		nfc.AddChain(whalewallChain)
	} else {
		if err := validateRegularOwnedChain(existingWhalewallChain); err != nil {
			return fmt.Errorf("invalid existing Whalewall chain: %w", err)
		}
		mainChainRules, err = nfc.GetRules(filterTable, whalewallChain)
		if err != nil {
			return fmt.Errorf("error listing rules of %q chain: %w", whalewallChainName, err)
		}
	}

	// add rule to jump from DOCKER-USER chain to whalewall chain
	dockerRules, err := nfc.GetRules(filterTable, dockerChain)
	if err != nil {
		return fmt.Errorf("error listing rules of %q chain: %w", dockerChainName, err)
	}
	dockerUserJumpRule := createJumpRule(dockerChain, whalewallChainName)
	if err := ensureJumpAtHead(nfc, r.logger, dockerUserJumpRule, dockerRules); err != nil {
		return fmt.Errorf("error repairing %q jump: %w", dockerChainName, err)
	}

	// add rule to jump from INPUT/OUTPUT chains to whalewall chain
	handleMainChain := func(name string, hook *nftables.ChainHook, mainChain *nftables.Chain) error {
		if mainChain == nil {
			r.logger.Debug("creating chain", zap.String("chain.name", name))
			// INPUT and OUTPUT sometimes don't exist in nftables
			mainChain = &nftables.Chain{
				Name:     name,
				Table:    filterTable,
				Hooknum:  hook,
				Priority: nftables.ChainPriorityFilter,
				Type:     nftables.ChainTypeFilter,
				Policy:   ref(nftables.ChainPolicyAccept),
			}
			nfc.AddChain(mainChain)
			nfc.InsertRule(createJumpRule(mainChain, whalewallChainName))
			return nil
		}

		rules, err := nfc.GetRules(filterTable, mainChain)
		if err != nil {
			return fmt.Errorf("error listing rules of %q chain: %w", name, err)
		}
		jumpRule := createJumpRule(mainChain, whalewallChainName)
		if err := ensureJumpAtHead(nfc, r.logger, jumpRule, rules); err != nil {
			return fmt.Errorf("error repairing %q jump: %w", name, err)
		}

		return nil
	}
	if err := handleMainChain(inputChainName, nftables.ChainHookInput, inputChain); err != nil {
		return err
	}
	if err := handleMainChain(outputChainName, nftables.ChainHookOutput, outputChain); err != nil {
		return err
	}

	// Create or validate the map that dispatches container addresses. Reusing
	// a same-name set with a different key/data schema can corrupt lookups or
	// make every subsequent update fail.
	if setMissing {
		if err := nfc.AddSet(desiredSet, nil); err != nil {
			return fmt.Errorf("error adding set %q: %w", containerAddrSetName, err)
		}
	}

	// Source dispatch must precede destination dispatch. GOTO makes this order
	// security-relevant: a source policy RETURN must resume the caller rather
	// than continue into the destination lookup. Repair missing, duplicate, or
	// misplaced dispatchers atomically and put both at the chain head.
	if err := ensureDispatchersAtHead(nfc, r.logger, mainChainRules); err != nil {
		return fmt.Errorf("error repairing Whalewall dispatchers: %w", err)
	}

	if err := nfc.Flush(); err != nil {
		return fmt.Errorf("error flushing nftables commands: %w", err)
	}

	return nil
}

func containerAddressSet() *nftables.Set {
	// nftables.Conn.AddSet mutates Set.ID and, for anonymous sets, Name.
	// Return a fresh value so concurrent reconciliation never races through a
	// package-global mutable Set.
	return &nftables.Set{
		Table:    filterTable,
		Name:     containerAddrSetName,
		IsMap:    true,
		KeyType:  nftables.TypeIPAddr,
		DataType: nftables.TypeVerdict,
	}
}

func containerAddressSetSchemaEqual(a, b *nftables.Set) bool {
	if a == nil || b == nil || a.Table == nil || b.Table == nil {
		return false
	}
	return a.Table.Name == b.Table.Name && a.Table.Family == b.Table.Family &&
		a.IsMap == b.IsMap && a.KeyType == b.KeyType && a.DataType == b.DataType &&
		a.Anonymous == b.Anonymous && a.Constant == b.Constant && a.Interval == b.Interval &&
		!a.Dynamic && !b.Dynamic && !a.HasTimeout && !b.HasTimeout && !a.Concatenation && !b.Concatenation
}

func validateRegularOwnedChain(chain *nftables.Chain) error {
	if chain == nil || chain.Table == nil || chain.Table.Name != filterTableName || chain.Table.Family != nftables.TableFamilyIPv4 {
		return errors.New("chain is not in the IPv4 filter table")
	}
	if chain.Hooknum != nil || chain.Priority != nil || chain.Policy != nil || chain.Device != "" {
		return errors.New("chain must be regular and unhooked")
	}
	if chain.Type != "" && chain.Type != nftables.ChainTypeFilter {
		return fmt.Errorf("chain has incompatible type %q", chain.Type)
	}
	return nil
}

func validateBaseChain(chain *nftables.Chain, hook *nftables.ChainHook) error {
	if chain == nil || chain.Table == nil || chain.Table.Name != filterTableName || chain.Table.Family != nftables.TableFamilyIPv4 {
		return errors.New("chain is not in the IPv4 filter table")
	}
	if chain.Type != nftables.ChainTypeFilter {
		return fmt.Errorf("chain type is %q, want filter", chain.Type)
	}
	if chain.Hooknum == nil || hook == nil || *chain.Hooknum != *hook {
		return errors.New("chain has the wrong netfilter hook")
	}
	if chain.Priority == nil || *chain.Priority != *nftables.ChainPriorityFilter {
		return errors.New("chain has the wrong filter priority")
	}
	if chain.Device != "" {
		return errors.New("chain unexpectedly targets a device")
	}
	return nil
}

func isUnconditionalJump(rule *nftables.Rule, chainName string) bool {
	verdicts := 0
	for i, expression := range rule.Exprs {
		switch e := expression.(type) {
		case *expr.Counter:
		case *expr.Verdict:
			verdicts++
			if i != len(rule.Exprs)-1 || e.Kind != expr.VerdictJump || e.Chain != chainName {
				return false
			}
		default:
			return false
		}
	}
	return verdicts == 1
}

func ensureJumpAtHead(nfc firewallClient, logger *zap.Logger, desired *nftables.Rule, current []*nftables.Rule) error {
	matchCount := 0
	for _, rule := range current {
		if rulesEqual(logger, desired, rule) {
			matchCount++
		}
	}
	if matchCount == 1 && len(current) != 0 && rulesEqual(logger, desired, current[0]) {
		return nil
	}
	for _, rule := range current {
		if !rulesEqual(logger, desired, rule) {
			continue
		}
		if err := nfc.DelRule(rule); err != nil {
			return err
		}
	}
	nfc.InsertRule(desired)
	return nil
}

func ensureDispatchersAtHead(nfc firewallClient, logger *zap.Logger, current []*nftables.Rule) error {
	srcCount, dstCount := 0, 0
	allRemainderSafe := true
	for _, rule := range current {
		if rulesEqual(logger, srcJumpRule, rule) {
			srcCount++
		}
		if rulesEqual(logger, dstJumpRule, rule) {
			dstCount++
		}
	}
	for _, rule := range current[min(2, len(current)):] {
		if !isSafeOwnedDropRule(rule) {
			allRemainderSafe = false
			break
		}
	}
	if srcCount == 1 && dstCount == 1 && len(current) >= 2 &&
		rulesEqual(logger, srcJumpRule, current[0]) && rulesEqual(logger, dstJumpRule, current[1]) && allRemainderSafe {
		return nil
	}
	for _, rule := range current {
		if !rulesEqual(logger, srcJumpRule, rule) && !rulesEqual(logger, dstJumpRule, rule) && isSafeOwnedDropRule(rule) {
			continue
		}
		if err := nfc.DelRule(rule); err != nil {
			return err
		}
	}
	// InsertRule prepends, so insert destination first to leave source first.
	nfc.InsertRule(dstJumpRule)
	nfc.InsertRule(srcJumpRule)
	return nil
}

func isSafeOwnedDropRule(rule *nftables.Rule) bool {
	if len(rule.UserData) == 0 || len(rule.Exprs) == 0 {
		return false
	}
	for i, expression := range rule.Exprs {
		switch e := expression.(type) {
		case *expr.Payload:
			if e.OperationType != expr.PayloadLoad {
				return false
			}
		case *expr.Meta:
			if e.SourceRegister {
				return false
			}
		case *expr.Ct:
			if e.SourceRegister {
				return false
			}
		case *expr.Cmp, *expr.Bitwise, *expr.Counter, *expr.Log:
		case *expr.Verdict:
			if i != len(rule.Exprs)-1 || e.Kind != expr.VerdictDrop {
				return false
			}
		default:
			return false
		}
	}
	verdict, ok := rule.Exprs[len(rule.Exprs)-1].(*expr.Verdict)
	return ok && verdict.Kind == expr.VerdictDrop
}

func createJumpRule(srcChain *nftables.Chain, dstChainName string) *nftables.Rule {
	return &nftables.Rule{
		Table: filterTable,
		Chain: srcChain,
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: dstChainName,
			},
		},
	}
}
