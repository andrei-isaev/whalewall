package whalewall

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"go.uber.org/zap"
)

const (
	dockerEventOrderingWindow = 100 * time.Millisecond
	dockerEventTestTimeout    = time.Second
)

func TestDockerEventLanesLetUnrelatedDeletePassSlowCreate(t *testing.T) {
	containerA := hardeningContainerWith(strings.Repeat("a", 64), "container-a", "172.30.0.2", map[string]string{enabledLabel: "true"})
	containerBID := strings.Repeat("b", 64)
	r := &RuleManager{
		logger:    zap.NewNop(),
		dockerCli: newMockDockerClient([]container.InspectResponse{containerA}),
		stopping:  make(chan struct{}),
		createCh:  make(chan containerDetails),
		deleteCh:  make(chan deleteDetails),
	}
	dispatcher := newDockerEventDispatcher(r)
	defer func() {
		close(r.stopping)
		dispatcher.closeAndWait()
	}()

	if !dispatcher.dispatch(context.Background(), events.Message{
		Type: events.ContainerEventType, Action: events.ActionStart,
		Actor: events.Actor{ID: containerA.ID},
	}) {
		t.Fatal("start event was not accepted")
	}
	createRequest := receiveCreateRequest(t, r.createCh)

	// Leave A waiting for its create result. B must still reach the independent
	// delete worker instead of being held behind A in the Docker stream reader.
	if !dispatcher.dispatch(context.Background(), events.Message{
		Type: events.ContainerEventType, Action: events.ActionDie,
		Actor: events.Actor{ID: containerBID, Attributes: map[string]string{"name": "container-b"}},
	}) {
		t.Fatal("die event was not accepted")
	}
	deleteRequest := receiveDeleteRequest(t, r.deleteCh)
	if deleteRequest.id != containerBID {
		t.Fatalf("delete request ID = %q, want %q", deleteRequest.id, containerBID)
	}
	deleteRequest.result <- nil
	createRequest.result <- nil
	dispatcher.closeAndWait()
}

func TestDockerEventLaneKeepsDieBeforeStartForSameContainer(t *testing.T) {
	containerID := strings.Repeat("c", 64)
	containerC := hardeningContainerWith(containerID, "container-c", "172.30.0.3", map[string]string{enabledLabel: "true"})
	r := &RuleManager{
		logger:    zap.NewNop(),
		dockerCli: newMockDockerClient([]container.InspectResponse{containerC}),
		stopping:  make(chan struct{}),
		createCh:  make(chan containerDetails),
		deleteCh:  make(chan deleteDetails),
	}
	dispatcher := newDockerEventDispatcher(r)
	defer func() {
		close(r.stopping)
		dispatcher.closeAndWait()
	}()

	if !dispatcher.dispatch(context.Background(), events.Message{
		Type: events.ContainerEventType, Action: events.ActionDie,
		Actor: events.Actor{ID: containerID, Attributes: map[string]string{"name": "container-c"}},
	}) {
		t.Fatal("die event was not accepted")
	}
	deleteRequest := receiveDeleteRequest(t, r.deleteCh)
	if !dispatcher.dispatch(context.Background(), events.Message{
		Type: events.ContainerEventType, Action: events.ActionStart,
		Actor: events.Actor{ID: containerID},
	}) {
		t.Fatal("start event was not accepted")
	}

	// Receiving the delete request proves the lane is blocked awaiting its
	// result. The following start is queued in that same lane and cannot inspect
	// or enqueue creation until deletion has been acknowledged.
	select {
	case request := <-r.createCh:
		t.Fatalf("start overtook die for the same container: %#v", request)
	case <-time.After(dockerEventOrderingWindow):
	}

	deleteRequest.result <- nil
	createRequest := receiveCreateRequest(t, r.createCh)
	if createRequest.container.ID != containerID {
		t.Fatalf("create request ID = %q, want %q", createRequest.container.ID, containerID)
	}
	createRequest.result <- nil
	dispatcher.closeAndWait()
}

func TestDockerEventDispatcherDrainsBeforeWorkerChannelsCanClose(t *testing.T) {
	containerD := hardeningContainerWith(strings.Repeat("d", 64), "container-d", "172.30.0.4", map[string]string{enabledLabel: "true"})
	r := &RuleManager{
		logger:    zap.NewNop(),
		dockerCli: newMockDockerClient([]container.InspectResponse{containerD}),
		stopping:  make(chan struct{}),
		createCh:  make(chan containerDetails),
		deleteCh:  make(chan deleteDetails),
	}
	dispatcher := newDockerEventDispatcher(r)
	defer func() {
		close(r.stopping)
		dispatcher.closeAndWait()
	}()

	if !dispatcher.dispatch(context.Background(), events.Message{
		Type: events.ContainerEventType, Action: events.ActionStart,
		Actor: events.Actor{ID: containerD.ID},
	}) {
		t.Fatal("start event was not accepted")
	}
	createRequest := receiveCreateRequest(t, r.createCh)
	drained := make(chan struct{})
	go func() {
		dispatcher.closeAndWait()
		close(drained)
	}()
	select {
	case <-drained:
		t.Fatal("dispatcher returned before accepted handler completed")
	case <-time.After(dockerEventOrderingWindow):
	}
	createRequest.result <- nil
	select {
	case <-drained:
	case <-time.After(dockerEventTestTimeout):
		t.Fatal("dispatcher did not finish draining completed handler")
	}
}

func TestDockerEventDispatcherReapsIdleLane(t *testing.T) {
	containerE := hardeningContainerWith(strings.Repeat("e", 64), "container-e", "172.30.0.5", map[string]string{enabledLabel: "true"})
	r := &RuleManager{
		logger:    zap.NewNop(),
		dockerCli: newMockDockerClient([]container.InspectResponse{containerE}),
		stopping:  make(chan struct{}),
		createCh:  make(chan containerDetails),
		deleteCh:  make(chan deleteDetails),
	}
	dispatcher := newDockerEventDispatcher(r)
	defer func() {
		close(r.stopping)
		dispatcher.closeAndWait()
	}()

	if !dispatcher.dispatch(context.Background(), events.Message{
		Type: events.ContainerEventType, Action: events.ActionStart,
		Actor: events.Actor{ID: containerE.ID},
	}) {
		t.Fatal("start event was not accepted")
	}
	createRequest := receiveCreateRequest(t, r.createCh)
	if len(dispatcher.lanes) != 1 {
		t.Fatalf("active lane count = %d, want 1", len(dispatcher.lanes))
	}
	createRequest.result <- nil
	deadline := time.Now().Add(dockerEventTestTimeout)
	for dispatcher.active() && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if dispatcher.active() {
		t.Fatal("event handler did not become idle")
	}
	dispatcher.reapIdle()
	if len(dispatcher.lanes) != 0 {
		t.Fatalf("idle lane count after reap = %d, want 0", len(dispatcher.lanes))
	}
	// Reusing the same Docker ID after reaping must allocate a fresh lane; it
	// must never send on the closed channel retained by the old worker.
	if !dispatcher.dispatch(context.Background(), events.Message{
		Type: events.ContainerEventType, Action: events.ActionStart,
		Actor: events.Actor{ID: containerE.ID},
	}) {
		t.Fatal("event for reaped container ID was not accepted")
	}
	reusedRequest := receiveCreateRequest(t, r.createCh)
	reusedRequest.result <- nil
	dispatcher.closeAndWait()
}

func receiveCreateRequest(t *testing.T, requests <-chan containerDetails) containerDetails {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(dockerEventTestTimeout):
		t.Fatal("timed out waiting for create request")
		return containerDetails{}
	}
}

func receiveDeleteRequest(t *testing.T, requests <-chan deleteDetails) deleteDetails {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(dockerEventTestTimeout):
		t.Fatal("timed out waiting for delete request")
		return deleteDetails{}
	}
}
