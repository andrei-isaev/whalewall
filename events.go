package whalewall

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/moby/moby/api/types/events"
)

// dockerEventLaneDepth bounds the amount of Docker event state retained per
// container. Docker emits only a small start/connect/disconnect/die burst for
// a lifecycle; backpressure is safer than allowing an unbounded queue.
const dockerEventLaneDepth = 16

type dockerEventEnvelope struct {
	ctx context.Context
	msg events.Message
}

type dockerEventLane struct {
	events  chan dockerEventEnvelope
	pending atomic.Int64
}

// dockerEventDispatcher preserves Docker stream order for each container but
// lets unrelated containers reach the existing create and delete workers
// independently. The watchDocker goroutine is the sole owner of lanes: it is
// the only caller of dispatch, reapIdle, and closeAndWait.
type dockerEventDispatcher struct {
	manager *RuleManager
	lanes   map[string]*dockerEventLane
	workers sync.WaitGroup
	activeN atomic.Int64
}

func newDockerEventDispatcher(manager *RuleManager) *dockerEventDispatcher {
	return &dockerEventDispatcher{
		manager: manager,
		lanes:   make(map[string]*dockerEventLane),
	}
}

// dispatch accepts an event unless manager shutdown has begun. A false return
// tells watchDocker to stop accepting stream events and begin draining lanes.
func (d *dockerEventDispatcher) dispatch(ctx context.Context, msg events.Message) bool {
	containerID := dockerEventContainerID(msg)
	if containerID == "" {
		// Keep malformed-event diagnostics and ignore filtered event types without
		// allocating a permanent lane with an empty key.
		d.manager.handleDockerEvent(ctx, msg)
		return true
	}

	d.reapIdle()
	lane := d.lanes[containerID]
	if lane == nil {
		lane = &dockerEventLane{events: make(chan dockerEventEnvelope, dockerEventLaneDepth)}
		d.lanes[containerID] = lane
		d.workers.Add(1)
		go d.runLane(lane)
	}

	lane.pending.Add(1)
	d.activeN.Add(1)
	envelope := dockerEventEnvelope{ctx: ctx, msg: msg}
	select {
	case lane.events <- envelope:
		return true
	case <-ctx.Done():
		lane.pending.Add(-1)
		d.activeN.Add(-1)
		return false
	case <-d.manager.stopping:
		lane.pending.Add(-1)
		d.activeN.Add(-1)
		return false
	}
}

func (d *dockerEventDispatcher) runLane(lane *dockerEventLane) {
	defer d.workers.Done()
	for envelope := range lane.events {
		func() {
			defer d.activeN.Add(-1)
			// Decrement the lane before the aggregate count. Observing activeN == 0
			// must guarantee reapIdle can also observe every lane as idle.
			defer lane.pending.Add(-1)
			d.manager.handleDockerEvent(envelope.ctx, envelope.msg)
		}()
	}
}

func (d *dockerEventDispatcher) active() bool {
	return d.activeN.Load() != 0
}

// reapIdle prevents one goroutine from being retained for every historical
// container ID. pending includes both the currently executing event and every
// queued event, and only the dispatcher owner can enqueue or close a lane.
func (d *dockerEventDispatcher) reapIdle() {
	for containerID, lane := range d.lanes {
		if lane.pending.Load() != 0 {
			continue
		}
		close(lane.events)
		delete(d.lanes, containerID)
	}
}

func (d *dockerEventDispatcher) closeAndWait() {
	for containerID, lane := range d.lanes {
		close(lane.events)
		delete(d.lanes, containerID)
	}
	d.workers.Wait()
}

func dockerEventContainerID(msg events.Message) string {
	switch {
	case msg.Type == events.ContainerEventType &&
		(msg.Action == events.ActionStart || msg.Action == events.ActionDie):
		return msg.Actor.ID
	case msg.Type == events.NetworkEventType &&
		(msg.Action == events.ActionConnect || msg.Action == events.ActionDisconnect):
		return msg.Actor.Attributes["container"]
	default:
		return ""
	}
}
