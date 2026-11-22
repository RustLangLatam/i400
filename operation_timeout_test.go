package i400

import (
	"context"
	"database/sql/driver"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// Hardening contract: no call into the driver can block for ever on a server
// that stops answering, including the calls that database/sql makes without a
// context of its own (Close, Rollback after the transaction's context ended,
// the legacy Prepare/Begin/Exec/Query entry points, statement close).

const stallTimeout = 150 * time.Millisecond

// stalledConn returns a Conn whose peer never reads or writes (net.Pipe is
// synchronous, so a Write with nobody reading blocks, as a full socket would).
func stalledConn(t *testing.T) (*Conn, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	c := &Conn{
		cfg:            Config{Host: "stalled.example", User: "U", OperationTimeout: stallTimeout, CommitmentControl: 1},
		netConn:        client,
		systemInfo:     &SystemInfo{},
		statementCache: map[string]*cachedStatement{},
	}
	return c, server
}

func within(t *testing.T, what string, limit time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	start := time.Now()
	go func() { defer close(done); f() }()
	select {
	case <-done:
		if d := time.Since(start); d > limit {
			t.Errorf("%s took %v, limit %v", what, d, limit)
		}
	case <-time.After(limit + 3*time.Second):
		t.Fatalf("%s is blocked on a stalled server", what)
	}
}

func TestCloseDoesNotBlockOnAStalledServer(t *testing.T) {
	c, _ := stalledConn(t)
	within(t, "Close", 4*stallTimeout, func() { _ = c.Close() })
}

func TestLegacyEntryPointsAreBoundedOnAStalledServer(t *testing.T) {
	c, _ := stalledConn(t)
	within(t, "Prepare", 4*stallTimeout, func() {
		if _, err := c.Prepare("SELECT 1 FROM SYSIBM.SYSDUMMY1"); err == nil {
			t.Error("Prepare succeeded against a stalled server")
		}
	})
	c, _ = stalledConn(t)
	within(t, "Begin", 4*stallTimeout, func() {
		if _, err := c.Begin(); err == nil {
			t.Error("Begin succeeded against a stalled server")
		}
	})
}

func TestStatementCloseIsBoundedOnAStalledServer(t *testing.T) {
	c, _ := stalledConn(t)
	s := newStmt(c, "SELECT 1 FROM SYSIBM.SYSDUMMY1", "STMT0001", 1, 0, nil, nil)
	within(t, "Stmt.Close", 4*stallTimeout, func() { _ = s.Close() })
}

func TestRollbackIsBoundedOnAStalledServer(t *testing.T) {
	c, _ := stalledConn(t)
	tx := &Tx{conn: c, ctx: context.Background()}
	within(t, "Rollback", 4*stallTimeout, func() {
		if err := tx.Rollback(); err == nil {
			t.Error("Rollback reported success against a stalled server")
		}
	})
}

// database/sql rolls a transaction back when its context ends, so Rollback must
// still reach the server with the begin context already cancelled.
func TestRollbackStillSendsWhenTheBeginContextIsCancelled(t *testing.T) {
	c, server := stalledConn(t)
	ctx, cancel := context.WithCancel(context.Background())
	tx := &Tx{conn: c, ctx: ctx}
	cancel()

	got := make(chan uint16, 1)
	go func() {
		packet, err := readPacket(server)
		if err != nil || len(packet) < 20 {
			got <- 0
			return
		}
		got <- binary.BigEndian.Uint16(packet[18:20])
		_ = server.Close()
	}()
	_ = tx.Rollback()
	select {
	case id := <-got:
		if id != FunctionRollback {
			t.Fatalf("first request after cancel had function id 0x%x, want rollback 0x%x", id, FunctionRollback)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no rollback request reached the server after the begin context was cancelled")
	}
}

// A server that accepts the TCP connection and never speaks TLS must not hold
// the dial past the caller's context, whether it expires or is cancelled.
func TestTLSHandshakeHonoursTheContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	cfg := Config{Host: "127.0.0.1", UseTLS: true}

	ctx, cancel := context.WithTimeout(context.Background(), stallTimeout)
	defer cancel()
	within(t, "TLS dial with a deadline", 4*stallTimeout, func() {
		if _, err := dialHostServer(ctx, cfg, port); err == nil {
			t.Error("TLS dial succeeded against a server that never answers")
		}
	})

	ctx2, cancel2 := context.WithCancel(context.Background())
	time.AfterFunc(stallTimeout, cancel2)
	within(t, "TLS dial cancelled", 4*stallTimeout, func() {
		if _, err := dialHostServer(ctx2, cfg, port); err == nil {
			t.Error("TLS dial succeeded against a server that never answers")
		}
	})
}

func TestOperationTimeoutConfig(t *testing.T) {
	cfg, err := ParseDSN("as400://U:P@host.example/LIB")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.operationTimeout(); got != defaultOperationTimeout {
		t.Fatalf("default = %v, want %v", got, defaultOperationTimeout)
	}
	cfg, err = ParseDSN("as400://U:P@host.example/LIB?operationTimeout=5s")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.operationTimeout(); got != 5*time.Second {
		t.Fatalf("operationTimeout = %v, want 5s", got)
	}
	if _, err := ParseDSN("as400://U:P@host.example/LIB?operationTimeout=-1s"); err == nil {
		t.Fatal("a negative operationTimeout was accepted")
	}
}

var _ driver.Tx = (*Tx)(nil)
