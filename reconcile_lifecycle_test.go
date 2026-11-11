package whalewall

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/google/nftables/expr"
	"github.com/moby/moby/api/types/container"
	"go.uber.org/zap"
)

func TestSyncRebuildsPeerChainsBeforePolicies(t *testing.T) {
	for _, warmDatabase := range []bool{false, true} {
		for _, sourceFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("warm=%t/sourceFirst=%t", warmDatabase, sourceFirst), func(t *testing.T) {
				r, creator := newHardeningTestManager(t)
				source := hardeningContainerWith(strings.Repeat("a", 64), "source", "172.30.0.2", map[string]string{
					enabledLabel: "true",
					rulesLabel:   "output:\n  - container: destination\n    network: default\n    proto: tcp\n    dst_ports: [443]",
				})
				destination := hardeningContainerWith(strings.Repeat("b", 64), "destination", "172.30.0.3", map[string]string{enabledLabel: "true"})
				containers := []container.InspectResponse{destination, source}
				if sourceFirst {
					containers[0], containers[1] = containers[1], containers[0]
				}
				r.dockerCli = newMockDockerClient(containers)
				if warmDatabase {
					for _, c := range []container.InspectResponse{destination, source} {
						if err := r.createContainerRules(context.Background(), c, true); err != nil {
							t.Fatal(err)
						}
					}
					// A reboot preserves SQLite but loses all kernel firewall objects.
					creator = newMockFirewallCreator(zap.NewNop())
					addMockDockerPrerequisites(t, creator.newMockFirewall())
					r.newFirewallClient = func() (firewallClient, error) { return creator.newMockFirewall(), nil }
					if err := r.createBaseRules(); err != nil {
						t.Fatal(err)
					}
				}
				if err := r.syncContainers(context.Background(), true); err != nil {
					t.Fatalf("first reconciliation must recover without a retry: %v", err)
				}
				creator.readBaseFirewall(func(base *mockFirewall) {
					for _, c := range containers {
						rules := base.chains[buildChainName(stripName(c.Name), c.ID)].Rules
						if len(rules) < 2 || !containsVerdict(rules[len(rules)-1].Exprs, expr.VerdictDrop) {
							t.Fatalf("%s lacks its allow rules or terminal drop: %#v", c.Name, rules)
						}
						if containsVerdict(rules[0].Exprs, expr.VerdictDrop) {
							t.Fatalf("%s remains quarantined after first reconciliation", c.Name)
						}
					}
				})
			})
		}
	}
}

type sourceInspectFailureClient struct {
	dockerClient
	id  string
	err error
}

func (c *sourceInspectFailureClient) ContainerInspect(ctx context.Context, id string) (container.InspectResponse, error) {
	if id == c.id {
		return container.InspectResponse{}, c.err
	}
	return c.dockerClient.ContainerInspect(ctx, id)
}

func TestWaitingSourceLifecycleDoesNotQuarantineDestination(t *testing.T) {
	for _, state := range []string{"deleted", "stopped", "unavailable"} {
		t.Run(state, func(t *testing.T) {
			r, creator := newHardeningTestManager(t)
			source := hardeningContainerWith(strings.Repeat("a", 64), "source", "172.30.0.2", map[string]string{
				enabledLabel: "true",
				rulesLabel:   "output:\n  - container: destination\n    network: default\n    proto: tcp\n    dst_ports: [443]",
			})
			destination := hardeningContainerWith(strings.Repeat("b", 64), "destination", "172.30.0.3", map[string]string{
				enabledLabel: "true",
				rulesLabel:   "output:\n  - network: default\n    ips: [1.1.1.1]\n    proto: tcp\n    dst_ports: [443]",
			})
			mock := newMockDockerClient([]container.InspectResponse{source, destination})
			r.dockerCli = mock
			for _, c := range []container.InspectResponse{destination, source} {
				if err := r.createContainerRules(context.Background(), c, true); err != nil {
					t.Fatal(err)
				}
			}
			rows, err := r.db.GetWaitingContainerRules(context.Background(), "destination")
			if err != nil || len(rows) == 0 {
				t.Fatalf("missing persisted relationship: %v", err)
			}
			switch state {
			case "deleted":
				r.dockerCli = &sourceInspectFailureClient{dockerClient: mock, id: source.ID, err: fmt.Errorf("removed: %w", errdefs.ErrNotFound)}
			case "stopped":
				mock.containers[0].State = &container.State{Running: false}
			case "unavailable":
				r.dockerCli = &sourceInspectFailureClient{dockerClient: mock, id: source.ID, err: errors.New("Docker API unavailable")}
			}
			err = r.createContainerRules(context.Background(), destination, false)
			if state == "unavailable" {
				if err == nil {
					t.Fatal("unexpected success with an unverified source")
				}
			} else if err != nil {
				t.Fatalf("obsolete source must not fail destination reconciliation: %v", err)
			}
			creator.readBaseFirewall(func(base *mockFirewall) {
				rules := base.chains[buildChainName("destination", destination.ID)].Rules
				if state == "unavailable" {
					if len(rules) != 1 || !containsVerdict(rules[0].Exprs, expr.VerdictDrop) {
						t.Fatalf("API failure did not quarantine policy: %#v", rules)
					}
					return
				}
				if len(rules) < 2 || containsVerdict(rules[0].Exprs, expr.VerdictDrop) {
					t.Fatalf("destination's unrelated allow was lost: %#v", rules)
				}
				for _, rule := range rules {
					if string(rule.UserData) == source.ID {
						t.Fatal("obsolete source still has access to the destination")
					}
				}
			})
		})
	}
}
