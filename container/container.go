package container

import (
	"context"
	"errors"
	"sync"

	"go.uber.org/zap"
)

// ErrContainerDeleted is used as a cancellation cause when a Docker die event
// supersedes in-progress rule creation. It lets callers distinguish that case
// from manager shutdown, where installed firewall state must be preserved.
var ErrContainerDeleted = errors.New("container deleted while policy was being created")

type Tracker struct {
	logger *zap.Logger
	mtx    sync.Mutex

	containers map[string]*processingContainer
}

type processingContainer struct {
	creating  bool
	cancel    context.CancelCauseFunc
	noCleanup bool
	done      chan struct{}
}

func NewTracker(logger *zap.Logger) *Tracker {
	return &Tracker{
		logger:     logger,
		containers: make(map[string]*processingContainer),
	}
}

func (c *Tracker) StartCreatingContainer(ctx context.Context, id string) (context.Context, func()) {
	ctx, cleanup, _ := c.addContainer(ctx, id, true)
	return ctx, cleanup
}

func (c *Tracker) StartDeletingContainer(ctx context.Context, id string) (context.Context, func(), bool) {
	return c.addContainer(ctx, id, false)
}

func (c *Tracker) addContainer(ctx context.Context, id string, creating bool) (context.Context, func(), bool) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	// if the same container is currently being processed, wait for it
	// to finish before starting a new operation on it
	cont, ok := c.containers[id]
	if ok {
		// we will reassign this map entry below, so prevent the cleanup
		// func from the current operation removing the new entry after
		// we return and the mutex unlocks
		cont.noCleanup = true

		// if the container is being created but will be deleted cancel
		// the current operation
		if cont.creating && !creating {
			c.logger.Debug("canceling container creation", zap.String("container.id", id[:12]))
			cont.cancel(ErrContainerDeleted)
			delete(c.containers, id)
			// Do not acknowledge the delete until the canceled creator's
			// deferred firewall/database cleanup has completed. This preserves
			// Docker die -> start ordering for restart-policy containers.
			<-cont.done
		} else {
			c.logger.Debug("waiting on container operation to finish", zap.String("container.id", id[:12]), zap.Bool("container.creating", cont.creating))
			<-cont.done
		}
	}

	ctx, cancel := context.WithCancelCause(ctx)
	newCont := &processingContainer{
		creating: creating,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
	c.containers[id] = newCont

	return ctx, func() {
		newCont.cancel(context.Canceled)
		close(newCont.done)

		c.mtx.Lock()
		defer c.mtx.Unlock()

		if newCont.noCleanup {
			return
		}
		delete(c.containers, id)
	}, true
}
