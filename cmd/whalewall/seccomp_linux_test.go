//go:build linux && !race

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const (
	seccompHelperEnv = "WHALEWALL_SECCOMP_TEST_HELPER"
	seccompDBEnv     = "WHALEWALL_SECCOMP_TEST_DB"
)

// TestSeccompRuntimeCompatibility uses a subprocess because a seccomp filter
// cannot be removed after it has been installed. The helper keeps the SQLite
// connection and its WAL files open before applying the production filter,
// matching whalewall's startup order.
func TestSeccompRuntimeCompatibility(t *testing.T) {
	if os.Getenv(seccompHelperEnv) == "1" {
		if err := exerciseSeccompRuntime(os.Getenv(seccompDBEnv)); err != nil {
			t.Fatal(err)
		}
		return
	}

	dbPath := filepath.Join(t.TempDir(), "seccomp.sqlite")
	cmd := exec.Command(os.Args[0], "-test.run=^TestSeccompRuntimeCompatibility$")
	cmd.Env = append(os.Environ(),
		seccompHelperEnv+"=1",
		seccompDBEnv+"="+dbPath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("seccomp compatibility helper failed: %v\n%s", err, output)
	}
}

func exerciseSeccompRuntime(dbPath string) error {
	if dbPath == "" {
		return errors.New("missing seccomp test database path")
	}

	ctx := context.Background()
	db, err := sql.Open("sqlite", dbPath+"?_txlock=immediate")
	if err != nil {
		return fmt.Errorf("open SQLite database: %w", err)
	}
	// A single retained connection ensures the post-filter operations use the
	// database, WAL, and shared-memory file descriptors opened during setup.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open SQLite connection: %w", err)
	}
	mmapFile, err := os.OpenFile(dbPath+".mmap", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open mmap test file: %w", err)
	}
	pageSize := os.Getpagesize()
	if err = mmapFile.Truncate(2 * int64(pageSize)); err != nil {
		return fmt.Errorf("size mmap test file: %w", err)
	}

	if _, err = conn.ExecContext(ctx, "PRAGMA journal_mode = WAL"); err != nil {
		return fmt.Errorf("enable SQLite WAL mode: %w", err)
	}
	if _, err = conn.ExecContext(ctx, "CREATE TABLE seed (id INTEGER PRIMARY KEY, payload BLOB NOT NULL)"); err != nil {
		return fmt.Errorf("create seed table: %w", err)
	}
	const seedBytes = 8 << 20
	if _, err = conn.ExecContext(ctx, "INSERT INTO seed (payload) VALUES (zeroblob(?))", seedBytes); err != nil {
		return fmt.Errorf("insert seed row: %w", err)
	}
	if _, err = conn.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("checkpoint seed data: %w", err)
	}
	if _, err = conn.ExecContext(ctx, "PRAGMA shrink_memory"); err != nil {
		return fmt.Errorf("release SQLite page cache: %w", err)
	}
	peekSockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create recvmsg probe socket pair: %w", err)
	}
	const peekPayload = "netlink-buffer-size-probe"
	if _, err = unix.Write(peekSockets[0], []byte(peekPayload)); err != nil {
		return fmt.Errorf("write recvmsg probe datagram: %w", err)
	}

	if _, err = installSeccompFilters(); err != nil {
		return fmt.Errorf("install seccomp filter: %w", err)
	}
	// mdlayher/netlink v1.11+ discovers a datagram's required buffer size with
	// this exact flag combination. Keep it in the post-filter regression so a
	// dependency update cannot silently kill live nftables reads.
	peeked, _, _, _, err := unix.Recvmsg(peekSockets[1], nil, nil, unix.MSG_PEEK|unix.MSG_TRUNC)
	if err != nil {
		return fmt.Errorf("peek recvmsg datagram length after installing seccomp: %w", err)
	}
	if peeked != len(peekPayload) {
		return fmt.Errorf("peeked recvmsg datagram length = %d, want %d", peeked, len(peekPayload))
	}
	for _, fd := range peekSockets {
		if err = unix.Close(fd); err != nil {
			return fmt.Errorf("close recvmsg probe socket: %w", err)
		}
	}

	// SQLite maps later WAL-index regions at nonzero page-aligned offsets.
	mapping, err := unix.Mmap(
		int(mmapFile.Fd()),
		int64(pageSize),
		pageSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED,
	)
	if err != nil {
		return fmt.Errorf("map nonzero WAL-style offset after installing seccomp: %w", err)
	}
	mapping[0] = 0x5a
	if err = unix.Munmap(mapping); err != nil {
		return fmt.Errorf("unmap WAL-style mapping after installing seccomp: %w", err)
	}
	if err = mmapFile.Close(); err != nil {
		return fmt.Errorf("close mmap test file after installing seccomp: %w", err)
	}

	// Go applies all three TCP keepalive tunables when dialing a TCP Docker
	// host. Exercise the count option that newer runtimes configure.
	socketFD, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("create TCP socket after installing seccomp: %w", err)
	}
	if err = unix.SetsockoptInt(socketFD, unix.SOL_TCP, unix.TCP_KEEPCNT, 9); err != nil {
		return fmt.Errorf("set TCP keepalive count after installing seccomp: %w", err)
	}
	// google/nftables checks both netlink socket buffers before each flush and
	// mdlayher/socket attempts the privileged FORCE variants before falling
	// back to the ordinary options when enlargement is required.
	for _, option := range []int{unix.SO_RCVBUF, unix.SO_SNDBUF} {
		bufferSize, getErr := unix.GetsockoptInt(socketFD, unix.SOL_SOCKET, option)
		if getErr != nil {
			return fmt.Errorf("get socket buffer option %d after installing seccomp: %w", option, getErr)
		}
		if bufferSize <= 0 {
			return fmt.Errorf("socket buffer option %d = %d, want a positive size", option, bufferSize)
		}
	}
	for _, option := range []int{unix.SO_RCVBUFFORCE, unix.SO_SNDBUFFORCE} {
		setErr := unix.SetsockoptInt(socketFD, unix.SOL_SOCKET, option, 1<<20)
		if setErr != nil && !errors.Is(setErr, unix.EPERM) {
			return fmt.Errorf("set forced socket buffer option %d after installing seccomp: %w", option, setErr)
		}
	}
	for _, option := range []int{unix.SO_RCVBUF, unix.SO_SNDBUF} {
		if err = unix.SetsockoptInt(socketFD, unix.SOL_SOCKET, option, 1<<20); err != nil {
			return fmt.Errorf("set socket buffer option %d after installing seccomp: %w", option, err)
		}
	}
	if err = unix.Close(socketFD); err != nil {
		return fmt.Errorf("close TCP socket after installing seccomp: %w", err)
	}

	// A goroutine that exits while locked causes the runtime to retire its OS
	// thread with SYS_EXIT rather than process-wide SYS_EXIT_GROUP.
	threadDone := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer close(threadDone)
		runtime.Goexit()
	}()
	<-threadDone

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin post-filter transaction: %w", err)
	}
	if _, err = tx.ExecContext(ctx, "CREATE TABLE post_filter (id INTEGER PRIMARY KEY, value TEXT NOT NULL)"); err != nil {
		return fmt.Errorf("create table after installing seccomp: %w", err)
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO post_filter (value) VALUES ('created')"); err != nil {
		return fmt.Errorf("insert after installing seccomp: %w", err)
	}

	// Read from the end of the uncached seed blob so SQLite must issue a
	// positioned read instead of satisfying the query from its page cache.
	var tail string
	if err = tx.QueryRowContext(ctx,
		"SELECT hex(substr(payload, ?, 1)) FROM seed WHERE id = 1",
		seedBytes,
	).Scan(&tail); err != nil {
		return fmt.Errorf("read after installing seccomp: %w", err)
	}
	if tail != "00" {
		return fmt.Errorf("unexpected seed tail %q", tail)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE post_filter SET value = 'updated' WHERE id = 1"); err != nil {
		return fmt.Errorf("update after installing seccomp: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit after installing seccomp: %w", err)
	}

	var value string
	if err = conn.QueryRowContext(ctx, "SELECT value FROM post_filter WHERE id = 1").Scan(&value); err != nil {
		return fmt.Errorf("read committed row after installing seccomp: %w", err)
	}
	if value != "updated" {
		return fmt.Errorf("unexpected committed value %q", value)
	}

	// Force the runtime to reserve and commit fresh heap arenas, decorate the
	// mappings, and perform a full GC while the filter is active.
	memory := make([]byte, 192<<20)
	for i := 0; i < len(memory); i += os.Getpagesize() {
		memory[i] = byte(i)
	}
	runtime.GC()
	debug.FreeOSMemory()
	runtime.KeepAlive(memory)

	// Force one refresh even if the test environment set GOMAXPROCS, then
	// remain alive long enough for the periodic Linux refresh as well.
	runtime.SetDefaultGOMAXPROCS()
	time.Sleep(2 * time.Second)

	if _, err = conn.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("checkpoint WAL after installing seccomp: %w", err)
	}
	// sql.Conn.Close returns the physical connection to the pool; sql.DB.Close
	// then closes it and exercises SQLite's WAL/SHM unmap and unlink path.
	if err = conn.Close(); err != nil {
		return fmt.Errorf("close SQLite connection after installing seccomp: %w", err)
	}
	if err = db.Close(); err != nil {
		return fmt.Errorf("close SQLite database after installing seccomp: %w", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, statErr := os.Stat(dbPath + suffix); statErr == nil {
			return fmt.Errorf("SQLite sidecar %q still exists after close", suffix)
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("stat SQLite sidecar %q after close: %w", suffix, statErr)
		}
	}
	return nil
}
