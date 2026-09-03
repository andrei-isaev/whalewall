package whalewall

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"go.uber.org/zap"
)

const composeDependsLabel = "com.docker.compose.depends_on"

func (r *RuleManager) syncContainers(ctx context.Context, quarantineFirst bool) error {
	filter := make(client.Filters).Add("label", enabledLabel)
	containers, err := r.dockerCli.ContainerList(ctx, client.ContainerListOptions{Filters: filter})
	if err != nil {
		return fmt.Errorf("error listing containers: %w", err)
	}
	// sort containers so those that don't have dependencies go first
	slices.SortFunc(containers, func(a, b dockercontainer.Summary) int {
		_, aHasLabels := a.Labels[composeDependsLabel]
		_, bHasLabels := b.Labels[composeDependsLabel]
		if aHasLabels == bHasLabels {
			return 0
		} else if !aHasLabels && bHasLabels {
			return -1
		}
		return 1
	})

	var syncErrs []error
	for _, c := range containers {
		truncID := c.ID[:12]
		container, err := r.dockerCli.ContainerInspect(ctx, c.ID)
		if err != nil {
			r.logger.Error("error inspecting container", zap.String("container.id", truncID), zap.Error(err))
			syncErrs = append(syncErrs, fmt.Errorf("inspect container %s: %w", truncID, err))
			continue
		}

		enabled, err := whalewallEnabled(container.Config.Labels)
		policyContainer := container
		if err != nil {
			r.logger.Error("error parsing label", zap.String("container.id", truncID), zap.String("label", enabledLabel), zap.Error(err))
			syncErrs = append(syncErrs, fmt.Errorf("parse %s label for container %s: %w", enabledLabel, truncID, err))
			// The presence of an invalid opt-in label is treated as intent to
			// enable Whalewall. Install only the enforcement floor.
			enabled = true
			policyContainer = denyOnlyContainer(container)
		}
		if !enabled {
			// deleteContainerRules removes only mappings owned by this container's
			// canonical chain, so a stale inspect cannot delete a new IP owner.
			if err := r.deleteContainerRules(ctx, container.ID, stripName(container.Name)); err != nil {
				syncErrs = append(syncErrs, fmt.Errorf("remove disabled container %s policy: %w", truncID, err))
			}
			continue
		}

		// Always attempt authoritative enforcement. A database preflight can
		// fail before the address is mapped to a drop chain and would leave an
		// opted-in container open.
		if err := r.createContainerRules(ctx, policyContainer, quarantineFirst); err != nil {
			syncErrs = append(syncErrs, fmt.Errorf("secure container %s: %w", truncID, err))
		}
	}

	return errors.Join(syncErrs...)
}

func whalewallEnabled(labels map[string]string) (bool, error) {
	e, ok := labels[enabledLabel]
	if !ok {
		return false, nil
	}

	switch {
	case strings.EqualFold(strings.TrimSpace(e), "true"):
		return true, nil
	case strings.EqualFold(strings.TrimSpace(e), "false"):
		return false, nil
	default:
		return false, fmt.Errorf("must be exactly true or false, got %q", e)
	}
}

func denyOnlyContainer(container dockercontainer.InspectResponse) dockercontainer.InspectResponse {
	if container.Config == nil {
		return container
	}
	config := *container.Config
	config.Labels = make(map[string]string, len(container.Config.Labels))
	for key, value := range container.Config.Labels {
		if key != rulesLabel {
			config.Labels[key] = value
		}
	}
	container.Config = &config
	return container
}
