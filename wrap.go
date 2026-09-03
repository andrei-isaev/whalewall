package whalewall

import (
	"context"
	"time"

	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

// wrappedDockerClient is a Docker client that respects the set timeout.
type wrappedDockerClient struct {
	timeout time.Duration
	client  *client.Client
}

func (w *wrappedDockerClient) Ping(ctx context.Context) (client.PingResult, error) {
	return withTimeout(ctx, w.timeout, func(ctx context.Context) (client.PingResult, error) {
		return w.client.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true})
	})
}

func (w *wrappedDockerClient) Info(ctx context.Context, options client.InfoOptions) (client.SystemInfoResult, error) {
	return withTimeout(ctx, w.timeout, func(ctx context.Context) (client.SystemInfoResult, error) {
		return w.client.Info(ctx, options)
	})
}

func (w *wrappedDockerClient) Events(ctx context.Context, options client.EventsListOptions) (<-chan events.Message, <-chan error) {
	result := w.client.Events(ctx, options)
	return result.Messages, result.Err
}

func (w *wrappedDockerClient) ContainerList(ctx context.Context, options client.ContainerListOptions) ([]dockercontainer.Summary, error) {
	return withTimeout(ctx, w.timeout, func(ctx context.Context) ([]dockercontainer.Summary, error) {
		result, err := w.client.ContainerList(ctx, options)
		return result.Items, err
	})
}

func (w *wrappedDockerClient) ContainerInspect(ctx context.Context, containerID string) (dockercontainer.InspectResponse, error) {
	return withTimeout(ctx, w.timeout, func(ctx context.Context) (dockercontainer.InspectResponse, error) {
		result, err := w.client.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
		return result.Container, err
	})
}

func (w *wrappedDockerClient) Close() error {
	return w.client.Close()
}
