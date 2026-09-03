package whalewall

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"syscall"

	"github.com/containerd/errdefs"
	"github.com/google/nftables"
	"go.uber.org/zap"
)

// Clear removes all nftables rules using the database initialized by
// NewRuleManager. Reopening it here would leak and replace the live handle.
func (r *RuleManager) Clear(ctx context.Context, _ string) error {
	return r.clearRules(ctx)
}

// clearRules removes all nftables rules created by whalewall.
func (r *RuleManager) clearRules(ctx context.Context) error {
	// Wipe firewall state globally before consulting per-container SQLite
	// metadata. This is intentionally independent of the strict hardened map
	// decoder so the new binary can clear baseline JUMP/name-based state.
	nfc, err := r.newFirewallClient()
	if err != nil {
		return fmt.Errorf("error creating netlink connection: %w", err)
	}

	// Delete every actual jump rule (including duplicates) by its kernel
	// handle. A newly constructed semantic lookalike has no handle and cannot
	// be deleted reliably by the real nftables client.
	var jumpDeleteErrs []error
	for _, chainName := range []string{dockerChainName, inputChainName, outputChainName} {
		chain := &nftables.Chain{
			Name:  chainName,
			Table: filterTable,
		}
		rules, err := nfc.GetRules(filterTable, chain)
		if err != nil {
			if errors.Is(err, syscall.ENOENT) {
				continue
			}
			jumpDeleteErrs = append(jumpDeleteErrs, fmt.Errorf("get rules of chain %s: %w", chainName, err))
			continue
		}

		jumpRule := createJumpRule(chain, whalewallChainName)
		for _, actual := range rules {
			if !rulesEqual(r.logger, jumpRule, actual) {
				continue
			}
			if err := nfc.DelRule(actual); err != nil {
				jumpDeleteErrs = append(jumpDeleteErrs, fmt.Errorf("delete jump from chain %s: %w", chainName, err))
			}
		}
	}
	if err := errors.Join(jumpDeleteErrs...); err != nil {
		return err
	}

	chains, err := nfc.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("error listing chains before clear: %w", err)
	}
	var ownedChains []*nftables.Chain
	for _, chain := range chains {
		if chain.Table.Name != filterTableName || (chain.Name != whalewallChainName && !strings.HasPrefix(chain.Name, chainPrefix)) {
			continue
		}
		if err := validateRegularOwnedChain(chain); err != nil {
			return fmt.Errorf("refusing to delete unsafe Whalewall chain collision: %w", err)
		}
		rules, err := nfc.GetRules(filterTable, chain)
		if err != nil {
			return fmt.Errorf("error listing rules of Whalewall chain %q: %w", chain.Name, err)
		}
		for _, rule := range rules {
			if err := nfc.DelRule(rule); err != nil {
				return fmt.Errorf("error deleting rule from Whalewall chain %q: %w", chain.Name, err)
			}
		}
		ownedChains = append(ownedChains, chain)
	}

	set, err := nfc.GetSetByName(filterTable, containerAddrSetName)
	if err != nil {
		if !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("error inspecting set %q before clear: %w", containerAddrSetName, err)
		}
	} else {
		if !containerAddressSetSchemaEqual(set, containerAddressSet()) {
			return fmt.Errorf("refusing to delete incompatible set collision %q", containerAddrSetName)
		}
		nfc.DelSet(set)
	}
	// Delete chains only after their rules, the address verdict map, and all
	// external jumps have been queued for deletion.
	for _, chain := range ownedChains {
		nfc.DelChain(chain)
	}
	if err := nfc.Flush(); err != nil {
		return fmt.Errorf("error flushing Whalewall clear transaction: %w", err)
	}

	containers, err := r.db.GetContainers(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("firewall cleared but database inventory could not be read: %w", err)
	}
	var metadataErrs []error
	for _, container := range containers {
		tx, err := r.db.Begin(ctx, r.logger)
		if err != nil {
			metadataErrs = append(metadataErrs, fmt.Errorf("begin metadata cleanup for %s: %w", container.ID[:12], err))
			continue
		}
		if err := r.deleteContainer(ctx, tx, container.ID); err != nil {
			tx.Rollback()
			metadataErrs = append(metadataErrs, fmt.Errorf("delete metadata for %s: %w", container.ID[:12], err))
		}
	}
	return errors.Join(metadataErrs...)
}

// cleanupRules removes nftables rules for containers that are now
// stopped or were removed.
func (r *RuleManager) cleanupRules(ctx context.Context) error {
	containers, err := r.db.GetContainers(ctx)
	if err != nil {
		return fmt.Errorf("error getting containers from database: %w", err)
	}

	var cleanupErrs []error
	for _, container := range containers {
		c, err := r.dockerCli.ContainerInspect(ctx, container.ID)
		truncID := container.ID[:12]
		if err != nil {
			if errdefs.IsNotFound(err) {
				contName := stripName(container.Name)
				r.logger.Info("cleaning rules of removed container", zap.String("container.id", truncID), zap.String("container.name", contName))
				if err := r.deleteContainerRules(ctx, container.ID, contName); err != nil {
					r.logger.Error("error deleting rules",
						zap.String("container.id", truncID),
						zap.String("container.name", container.Name),
						zap.Error(err),
					)
					cleanupErrs = append(cleanupErrs, fmt.Errorf("clean removed container %s: %w", truncID, err))
				}
			} else {
				r.logger.Error("error inspecting container", zap.String("container.id", truncID), zap.Error(err))
				cleanupErrs = append(cleanupErrs, fmt.Errorf("inspect container %s: %w", truncID, err))
			}
			continue
		}
		contName := stripName(container.Name)
		if !c.State.Running {
			r.logger.Info("cleaning rules of stopped container", zap.String("container.id", truncID), zap.String("container.name", contName))
			if err := r.deleteContainerRules(ctx, container.ID, contName); err != nil {
				r.logger.Error("error deleting rules",
					zap.String("container.id", truncID),
					zap.String("container.name", container.Name),
					zap.Error(err),
				)
				cleanupErrs = append(cleanupErrs, fmt.Errorf("clean stopped container %s: %w", truncID, err))
			}
		} else {
			r.logger.Debug("not cleaning rules of running container", zap.String("container.id", truncID), zap.String("container.name", contName))
		}
	}

	return errors.Join(cleanupErrs...)
}

// deleteRules removes nftables rules for stopped or killed containers.
func (r *RuleManager) deleteRules(ctx context.Context) {
	for details := range r.deleteCh {
		id := details.id
		truncID := id[:12]
		name, err := r.db.GetContainerName(ctx, id)
		var lookupErr error
		if err != nil {
			// Firewall cleanup is ID-based and must never be gated on a database
			// lookup. A metadata commit may have failed after the fail-closed
			// floor was installed, or SQLite itself may currently be unavailable.
			name = stripName(details.name)
			if !errors.Is(err, sql.ErrNoRows) {
				lookupErr = fmt.Errorf("get container name: %w", err)
				r.logger.Error("error getting name of container", zap.String("container.id", truncID), zap.Error(err))
			}
		}

		r.logger.Info("deleting rules", zap.String("container.id", truncID), zap.String("container.name", name))
		deleteErr := r.deleteContainerRules(ctx, id, name)
		if deleteErr != nil {
			r.logger.Error("error deleting rules",
				zap.String("container.id", truncID),
				zap.String("container.name", name),
				zap.Error(deleteErr),
			)
		}
		sendDeleteResult(details, errors.Join(lookupErr, deleteErr))
	}
}

func sendDeleteResult(details deleteDetails, err error) {
	if details.result != nil {
		details.result <- err
	}
}

// deleteContainerRules removes all nftables rules for a container.
func (r *RuleManager) deleteContainerRules(ctx context.Context, id, name string) error {
	logger := r.logger.With(zap.String("container.id", id[:12]), zap.String("container.name", name))
	ctx, cleanup, ok := r.containerTracker.StartDeletingContainer(ctx, id)
	if !ok {
		logger.Info("container creation canceled, skipping deletion")
		return nil
	}
	defer cleanup()
	r.policyMu.Lock()
	defer r.policyMu.Unlock()
	return r.deleteContainerRulesUntracked(ctx, id, name)
}

// deleteContainerRulesUntracked requires policyMu to be held by the caller.
// createContainerRules also calls it from rollback while already holding that
// lock, so locking inside this helper would deadlock canceled creation.
func (r *RuleManager) deleteContainerRulesUntracked(ctx context.Context, id, name string) error {
	logger := r.logger.With(zap.String("container.id", id[:12]), zap.String("container.name", name))
	nfc, err := r.newFirewallClient()
	if err != nil {
		return fmt.Errorf("error creating netlink connection: %w", err)
	}

	chains, err := nfc.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("error listing IPv4 chains: %w", err)
	}
	chainName := buildChainName(name, id)
	var cleanupErrs []error
	var ownChain *nftables.Chain
	var ownRules []*nftables.Rule
	// A destination container's ID is used as UserData on outbound rules in
	// arbitrary source-container chains. Scan every Whalewall-owned chain so a
	// destination death cannot leave an allow rule behind for later IP reuse.
	for _, candidate := range chains {
		if candidate.Table.Name != filterTableName {
			continue
		}
		if candidate.Name == chainName {
			if err := validateRegularOwnedChain(candidate); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("unsafe container-chain name collision %s: %w", candidate.Name, err))
				continue
			}
			ownChain = candidate
			ownRules, err = nfc.GetRules(filterTable, candidate)
			if err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("get rules of own chain %s: %w", candidate.Name, err))
			}
			continue
		}
		if candidate.Name != whalewallChainName && !strings.HasPrefix(candidate.Name, chainPrefix) {
			continue
		}
		if err := validateRegularOwnedChain(candidate); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("unsafe Whalewall chain %s: %w", candidate.Name, err))
			continue
		}
		rules, err := nfc.GetRules(filterTable, candidate)
		if err != nil {
			if !errors.Is(err, syscall.ENOENT) {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("get rules of chain %s: %w", candidate.Name, err))
			}
			continue
		}
		if err := deleteRulesFromContainer(nfc, rules, id); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("delete rules from chain %s: %w", candidate.Name, err))
		}
	}

	if err := errors.Join(cleanupErrs...); err != nil {
		return fmt.Errorf("error preparing firewall cleanup: %w", err)
	}

	// Serialize the map snapshot, deletion, and ownership-database commit with
	// address replacement. This closes the final IP-reuse race between an old
	// owner's cleanup and a new owner's metadata transaction.
	r.addressMapMu.Lock()
	defer r.addressMapMu.Unlock()

	set := containerAddressSet()
	currentMappings, err := nfc.GetSetElements(set)
	if err != nil {
		return fmt.Errorf("error listing container address mappings: %w", err)
	}
	var addressElements []nftables.SetElement
	for _, element := range currentMappings {
		verdict, err := containerMappingVerdict(element)
		if err != nil {
			return fmt.Errorf("invalid container address mapping for key %x: %w", element.Key, err)
		}
		if verdict.Chain == chainName {
			addressElements = append(addressElements, nftables.SetElement{Key: element.Key})
		}
	}
	if len(addressElements) != 0 {
		if err := nfc.SetDeleteElements(set, addressElements); err != nil {
			return fmt.Errorf("error marshaling container address mapping deletion: %w", err)
		}
	}

	// A real nftables chain cannot be deleted while it still has rules. Queue
	// deletion of every actual handled rule before DELCHAIN in the same batch.
	if ownChain != nil {
		for _, rule := range ownRules {
			if err := nfc.DelRule(rule); err != nil {
				return fmt.Errorf("error deleting rule from own chain %s: %w", chainName, err)
			}
		}
		nfc.DelChain(ownChain)
	}
	if err := nfc.Flush(); err != nil {
		// Keep the SQLite row as retry state. Periodic reconciliation will
		// retry any partially completed nftables cleanup.
		return fmt.Errorf("incomplete firewall cleanup for chain %s: %w", chainName, err)
	}

	// Firewall state is authoritative for isolation and must be removed even
	// when SQLite is unavailable. Begin the metadata transaction only after the
	// packet-atomic nftables cleanup has succeeded; a DB failure leaves the row
	// in place as retry/audit state.
	tx, err := r.db.Begin(ctx, logger)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	logger.Debug("deleting from database")
	if err := r.deleteContainer(ctx, tx, id); err != nil {
		return fmt.Errorf("error deleting container from database: %w", err)
	}

	return nil
}

// deleteRulesFromContainer removes nftables rules that belong to a container
// specified by id.
func deleteRulesFromContainer(nfc firewallClient, rules []*nftables.Rule, id string) error {
	idb := []byte(id)
	var deleteErrs []error
	for _, rule := range rules {
		if !bytes.Equal(idb, rule.UserData) {
			continue
		}

		if err := nfc.DelRule(rule); err != nil {
			deleteErrs = append(deleteErrs, err)
			continue
		}
	}
	return errors.Join(deleteErrs...)
}
