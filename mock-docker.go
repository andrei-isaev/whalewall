package whalewall

import (
	"context"
	"errors"
	"slices"
	"sync"

	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"
)

type dockerClient interface {
	Ping(ctx context.Context) (client.PingResult, error)
	Info(ctx context.Context, options client.InfoOptions) (client.SystemInfoResult, error)
	Events(ctx context.Context, options client.EventsListOptions) (<-chan events.Message, <-chan error)
	ContainerList(ctx context.Context, options client.ContainerListOptions) ([]dockercontainer.Summary, error)
	ContainerInspect(ctx context.Context, containerID string) (dockercontainer.InspectResponse, error)
	Close() error
}

type mockDockerClient struct {
	mtx sync.RWMutex

	eventCh    chan events.Message
	containers []dockercontainer.InspectResponse
	info       system.Info
	infoErr    error
}

func newMockDockerClient(containers []dockercontainer.InspectResponse) *mockDockerClient {
	return &mockDockerClient{
		eventCh:    make(chan events.Message),
		containers: containers,
		info: system.Info{FirewallBackend: &system.FirewallInfo{
			Driver: "iptables",
		}},
	}
}

func (m *mockDockerClient) Ping(_ context.Context) (client.PingResult, error) {
	return client.PingResult{}, nil
}

func (m *mockDockerClient) Info(_ context.Context, _ client.InfoOptions) (client.SystemInfoResult, error) {
	return client.SystemInfoResult{Info: m.info}, m.infoErr
}

func (m *mockDockerClient) Events(_ context.Context, _ client.EventsListOptions) (<-chan events.Message, <-chan error) {
	return m.eventCh, nil
}

func (m *mockDockerClient) ContainerList(_ context.Context, _ client.ContainerListOptions) ([]dockercontainer.Summary, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	listedConts := make([]dockercontainer.Summary, len(m.containers))
	for i, cont := range m.containers {
		listedConts[i] = dockercontainer.Summary{
			ID:     cont.ID,
			Names:  []string{cont.Name},
			Labels: cont.Config.Labels,
		}
	}

	return listedConts, nil
}

func (m *mockDockerClient) ContainerInspect(_ context.Context, containerID string) (dockercontainer.InspectResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	i := slices.IndexFunc(m.containers, func(c dockercontainer.InspectResponse) bool {
		return c.ID == containerID
	})
	if i == -1 {
		return dockercontainer.InspectResponse{}, errors.New("container not found")
	}

	return m.containers[i], nil
}

func (m *mockDockerClient) Close() error {
	return nil
}
