package whalewall

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/google/nftables"
	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"

	"github.com/capnspacehook/whalewall/container"
	"github.com/capnspacehook/whalewall/database"
)

const (
	dummyID   = "dummy_id"
	dummyName = "dummy_name"

	enabledLabel = "whalewall.enabled"
	rulesLabel   = "whalewall.rules"

	defaultReconcileInterval = 30 * time.Second
	initialReconnectDelay    = time.Second
	maximumReconnectDelay    = 30 * time.Second
)

//go:embed database/schema.sql
var dbSchema string

type RuleManager struct {
	wg       sync.WaitGroup
	stopping chan struct{}
	done     chan struct{}

	logger *zap.Logger

	newDockerClient   dockerClientCreator
	newFirewallClient firewallClientCreator

	containerTracker *container.Tracker

	createCh chan containerDetails
	deleteCh chan deleteDetails

	db        database.DB
	dockerCli dockerClient

	reconcileInterval time.Duration
	addressMapMu      sync.Mutex
	// policyMu serializes policy snapshots and nftables application across
	// containers. A source container can own rules in a destination container's
	// chain, so create and delete transactions must not overtake each other.
	policyMu sync.Mutex
}

type dockerClientCreator func() (dockerClient, error)

type firewallClientCreator func() (firewallClient, error)

type containerDetails struct {
	container dockercontainer.InspectResponse
	isNew     bool
	result    chan error
}

type deleteDetails struct {
	id     string
	name   string
	result chan error
}

func NewRuleManager(ctx context.Context, logger *zap.Logger, dbFile string, timeout time.Duration) (*RuleManager, error) {
	r := RuleManager{
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
		logger:   logger,
		newDockerClient: func() (dockerClient, error) {
			dc, err := client.New(client.FromEnv, client.WithAPIVersionNegotiation())
			if err != nil {
				return nil, err
			}
			return &wrappedDockerClient{
				timeout: timeout,
				client:  dc,
			}, nil
		},
		newFirewallClient: func() (firewallClient, error) {
			return nftables.New()
		},
		containerTracker:  container.NewTracker(logger),
		createCh:          make(chan containerDetails),
		deleteCh:          make(chan deleteDetails),
		reconcileInterval: defaultReconcileInterval,
	}
	err := r.initDB(ctx, dbFile)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func (r *RuleManager) Start(ctx context.Context) error {
	if err := r.init(ctx); err != nil {
		return err
	}
	eventsSince := time.Now().UTC()
	if err := r.createBaseRules(); err != nil {
		return fmt.Errorf("error creating base rules: %w", err)
	}

	// Cleanup and synchronization are independent best-effort phases. A stale
	// container that cannot be cleaned must not prevent a currently running,
	// opted-in container from receiving its fail-closed floor. Keep the manager
	// alive so periodic reconciliation can retry every incomplete operation.
	cleanupErr := r.cleanupRules(ctx)
	syncErr := r.syncContainers(ctx, true)
	if err := errors.Join(cleanupErr, syncErr); err != nil {
		r.logger.Error("initial firewall reconciliation incomplete; continuing fail-closed and retrying periodically", zap.Error(err))
	}

	r.wg.Add(3)
	go func() {
		defer r.wg.Done()
		r.createRules(ctx)
	}()
	go func() {
		defer r.wg.Done()
		r.deleteRules(ctx)
	}()
	go func() {
		defer r.wg.Done()
		defer close(r.createCh)
		defer close(r.deleteCh)
		r.watchDocker(ctx, eventsSince)
	}()
	go func() {
		r.wg.Wait()
		close(r.done)
	}()

	return nil
}

func (r *RuleManager) watchDocker(ctx context.Context, since time.Time) {
	ticker := time.NewTicker(r.reconcileInterval)
	defer ticker.Stop()
	dispatcher := newDockerEventDispatcher(r)
	// The Start goroutine closes createCh/deleteCh only after watchDocker
	// returns. Drain every accepted lane first so no handler can send to a
	// closed worker channel.
	defer dispatcher.closeAndWait()
	reconnectDelay := initialReconnectDelay

	for {
		messages, streamErrs := addFilters(ctx, r.dockerCli, since)
	stream:
		for {
			select {
			case msg, ok := <-messages:
				if !ok {
					break stream
				}
				reconnectDelay = initialReconnectDelay
				if !dispatcher.dispatch(ctx, msg) {
					return
				}
			case err, ok := <-streamErrs:
				if !ok {
					break stream
				}
				if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
					r.logger.Error("error reading docker event stream", zap.Error(err))
				}
				break stream
			case <-ticker.C:
				dispatcher.reapIdle()
				if dispatcher.active() {
					r.logger.Debug("deferring firewall reconciliation while Docker events are active")
					continue
				}
				if err := r.reconcile(ctx); err != nil {
					r.logger.Error("error reconciling firewall state", zap.Error(err))
				}
			case <-ctx.Done():
				return
			case <-r.stopping:
				return
			}
		}

		// Back off even when Ping succeeds. A permanently closed Events
		// stream (for example due to an API or permission error) must not
		// become a tight reconnect/reconcile loop.
		if !r.waitForReconnect(ctx, reconnectDelay) {
			return
		}
		reconnectDelay = min(reconnectDelay*2, maximumReconnectDelay)
		if !r.waitForDocker(ctx) {
			return
		}
		// Capture a cursor before taking the state snapshot. Replaying from
		// this point covers events that occur while reconciliation runs.
		since = time.Now().UTC()
		dispatcher.reapIdle()
		if dispatcher.active() {
			r.logger.Debug("deferring post-reconnect reconciliation while Docker events are active")
			continue
		}
		if err := r.reconcile(ctx); err != nil {
			r.logger.Error("error reconciling after Docker event stream interruption", zap.Error(err))
		}
	}
}

func (r *RuleManager) waitForReconnect(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	case <-r.stopping:
		return false
	}
}

func (r *RuleManager) handleDockerEvent(ctx context.Context, msg events.Message) {
	if msg.Type == events.ContainerEventType && msg.Action == events.ActionDie {
		if msg.Actor.ID == "" {
			r.logger.Error("Docker container die event is missing container ID")
			return
		}
		// Delete tracked policy even if the current label value is malformed;
		// otherwise a quarantined container can leave an address-map entry
		// behind and block a later container that reuses the address.
		if err := r.awaitContainerDelete(ctx, msg.Actor.ID, msg.Actor.Attributes["name"]); err != nil {
			r.logger.Error("error deleting container policy", zap.String("container.id", msg.Actor.ID), zap.Error(err))
		}
		return
	}

	containerID := msg.Actor.ID
	switch {
	case msg.Type == events.ContainerEventType && msg.Action == events.ActionStart:
		if containerID == "" {
			r.logger.Error("Docker container start event is missing container ID")
			return
		}
	case msg.Type == events.NetworkEventType && (msg.Action == events.ActionConnect || msg.Action == events.ActionDisconnect):
		containerID = msg.Actor.Attributes["container"]
		if containerID == "" {
			r.logger.Error("Docker network event is missing container ID", zap.String("network.id", msg.Actor.ID))
			return
		}
	default:
		return
	}

	container, err := r.dockerCli.ContainerInspect(ctx, containerID)
	if err != nil {
		r.logger.Error("error inspecting container", zap.String("container.id", containerID), zap.Error(err))
		return
	}
	if msg.Type == events.NetworkEventType && (container.State == nil || !container.State.Running) {
		// Docker commonly emits disconnect after die. Never recreate policy
		// for a stopped container from that trailing network event.
		return
	}
	enabled, err := whalewallEnabled(container.Config.Labels)
	forceDeny := err != nil
	if err != nil {
		r.logger.Error("error parsing label", zap.String("container.id", containerID), zap.String("label", enabledLabel), zap.Error(err))
		enabled = true
	}
	if !enabled {
		// Cleanup is ID/chain-owner based. Never delete a verdict-map element
		// merely because this stale inspection reports the same address: Docker
		// may already have assigned that address to a different protected owner.
		if err := r.awaitContainerDelete(ctx, containerID, container.Name); err != nil {
			r.logger.Error("error removing disabled container policy", zap.String("container.id", containerID), zap.Error(err))
		}
		return
	}
	if forceDeny {
		container = denyOnlyContainer(container)
	}
	result := make(chan error, 1)
	// Never gate enforcement on a database read. createContainerRules is
	// authoritative and idempotent; a database failure must happen only after
	// the nftables fail-closed floor is installed.
	details := containerDetails{container: container, isNew: true, result: result}
	select {
	case r.createCh <- details:
	case <-ctx.Done():
		return
	case <-r.stopping:
		return
	}
	select {
	case err := <-result:
		if err != nil {
			r.logger.Error("error applying container policy", zap.String("container.id", containerID), zap.Error(err))
		}
	case <-ctx.Done():
	case <-r.stopping:
	}
}

func (r *RuleManager) awaitContainerDelete(ctx context.Context, id, name string) error {
	result := make(chan error, 1)
	details := deleteDetails{id: id, name: name, result: result}
	select {
	case r.deleteCh <- details:
	case <-ctx.Done():
		return ctx.Err()
	case <-r.stopping:
		return context.Canceled
	}
	// Preserve Docker event order. In particular, a restart-policy start for
	// the same ID must not overtake the preceding policy deletion.
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-r.stopping:
		return context.Canceled
	}
}

func (r *RuleManager) waitForDocker(ctx context.Context) bool {
	delay := initialReconnectDelay
	for {
		if _, err := r.dockerCli.Ping(ctx); err == nil {
			if err := r.validateDockerFirewallBackend(ctx); err != nil {
				r.logger.Error("unsupported Docker firewall backend", zap.Error(err), zap.Duration("retry_in", delay))
			} else {
				return true
			}
		} else {
			r.logger.Error("error connecting to Docker daemon", zap.Error(err), zap.Duration("retry_in", delay))
		}

		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-r.stopping:
			timer.Stop()
			return false
		}
		delay = min(delay*2, maximumReconnectDelay)
	}
}

func (r *RuleManager) reconcile(ctx context.Context) error {
	if err := r.createBaseRules(); err != nil {
		return fmt.Errorf("error repairing base rules: %w", err)
	}
	cleanupErr := r.cleanupRules(ctx)
	syncErr := r.syncContainers(ctx, false)
	return errors.Join(cleanupErr, syncErr)
}

func (r *RuleManager) init(ctx context.Context) error {
	dockerCli, err := r.newDockerClient()
	if err != nil {
		return fmt.Errorf("error creating docker client: %w", err)
	}
	r.dockerCli = dockerCli
	_, err = r.dockerCli.Ping(ctx)
	if err != nil {
		return fmt.Errorf("error connecting to docker daemon: %w", err)
	}
	return r.validateDockerFirewallBackend(ctx)
}

func (r *RuleManager) validateDockerFirewallBackend(ctx context.Context) error {
	result, err := r.dockerCli.Info(ctx, client.InfoOptions{})
	if err != nil {
		return fmt.Errorf("cannot verify Docker firewall backend: %w", err)
	}
	backend := result.Info.FirewallBackend
	if backend == nil || backend.Driver == "" {
		return errors.New("Docker did not report its firewall backend; Whalewall requires Docker API 1.49+ with firewall-backend=iptables backed by nftables")
	}
	if backend.Driver != "iptables" {
		return fmt.Errorf("unsupported Docker firewall backend %q: Whalewall requires firewall-backend=iptables backed by nftables", backend.Driver)
	}
	return nil
}

func (r *RuleManager) initDB(ctx context.Context, dbFile string) error {
	// create data directory if it doesn't exist
	dbDir := filepath.Dir(dbFile)
	if _, err := os.Stat(dbDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			r.logger.Info("creating data directory", zap.String("data.dir", dbDir))
			if err := os.MkdirAll(dbDir, 0o750); err != nil {
				return fmt.Errorf("error creating data directory: %w", err)
			}
		} else {
			return err
		}
	}

	var dbNotExist bool
	if _, err := os.Stat(dbFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			dbNotExist = true
		} else {
			return err
		}
	}

	sqlDB, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		return fmt.Errorf("error opening database: %w", err)
	}
	closeOnError := true
	var dbHandle database.DB
	defer func() {
		if closeOnError {
			if dbHandle != nil {
				_ = dbHandle.Close()
			} else {
				_ = sqlDB.Close()
			}
		}
	}()
	// Keep the single physical SQLite connection opened before Landlock and
	// seccomp are applied. database/sql must not attempt a later SYS_OPEN, and
	// the per-connection safety pragmas are guaranteed for the whole runtime.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("error opening SQLite connection: %w", err)
	}
	// create database schema if a SQLite database didn't exist
	if dbNotExist {
		if _, err := sqlDB.ExecContext(ctx, dbSchema); err != nil {
			return fmt.Errorf("error creating tables in database: %w", err)
		}
	}
	dbHandle, err = database.NewDB(ctx, sqlDB)
	if err != nil {
		return fmt.Errorf("error preparing database queries: %w", err)
	}
	// SQLite will lazily create WAL files when something is first written, and
	// Landlock requires those files to exist before its rules are installed.
	// Do this for existing databases too: a clean checkpoint may have removed
	// their previous WAL/SHM files.
	tx, err := dbHandle.Begin(ctx, r.logger)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = tx.AddContainer(ctx, dummyID, dummyName); err != nil {
		return fmt.Errorf("error adding container to database: %w", err)
	}
	err = tx.DeleteContainer(ctx, dummyID)
	if err != nil {
		return fmt.Errorf("error deleting container in database: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error committing database initialization: %w", err)
	}

	r.db = dbHandle
	closeOnError = false
	return nil
}

func sqliteDSN(dbFile string) string {
	query := make(url.Values)
	query.Set("_foreign_keys", "1")
	query.Set("_busy_timeout", "1000")
	query.Set("_journal_mode", "WAL")
	query.Set("_txlock", "immediate")
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(dbFile), RawQuery: query.Encode()}).String()
}

func addFilters(ctx context.Context, docker dockerClient, since time.Time) (<-chan events.Message, <-chan error) {
	filter := make(client.Filters).
		Add("type", string(events.ContainerEventType), string(events.NetworkEventType)).
		Add("event", string(events.ActionStart), string(events.ActionDie), string(events.ActionConnect), string(events.ActionDisconnect))
	return docker.Events(ctx, client.EventsListOptions{
		Filters: filter,
		Since:   strconv.FormatInt(since.Unix(), 10),
	})
}

func (r *RuleManager) Done() <-chan struct{} {
	return r.done
}

func (r *RuleManager) Stop() {
	close(r.stopping)
	r.wg.Wait()

	if r.dockerCli != nil {
		if err := r.dockerCli.Close(); err != nil {
			r.logger.Error("error closing docker client", zap.Error(err))
		}
	}
	if r.db != nil {
		if err := r.db.Close(); err != nil {
			r.logger.Error("error closing database", zap.Error(err))
		}
	}
}
