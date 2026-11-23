package i400

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// Review findings 6, 7 and 8.

// Finding 6: Close does not wait for an operation that holds the connection (a stalled
// query): it closes the socket, which ends that operation, and it never waits unbounded
// on the operation mutex.
func TestCloseIsBoundedWhileAnOperationHoldsTheConnection(t *testing.T) {
	c, server := stalledConn(t)
	c.opMu.Lock() // an in-flight request that never finishes
	defer c.opMu.Unlock()
	within(t, "Close while an operation is in flight", 4*stallTimeout, func() { _ = c.Close() })
	// The socket is closed: the peer sees it end.
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Error("the socket was left open")
	}
}

func TestSocketTimeoutHasASaneDefault(t *testing.T) {
	cfg, err := ParseDSN("as400s://U:P@host.example/LIB")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SocketTimeout != defaultSocketTimeout || defaultSocketTimeout < time.Minute {
		t.Fatalf("default = %v", cfg.SocketTimeout)
	}
	cfg, _ = ParseDSN("as400s://U:P@host.example/LIB?socketTimeout=0")
	if cfg.SocketTimeout != 0 {
		t.Errorf("an explicit 0 disables it, got %v", cfg.SocketTimeout)
	}
	conn, err := NewConnector(Config{Host: "h"})
	if err != nil || conn.cfg.SocketTimeout != defaultSocketTimeout {
		t.Errorf("NewConnector default = %v, %v", conn.cfg.SocketTimeout, err)
	}
	conn, _ = NewConnector(Config{Host: "h", SocketTimeout: -1})
	if conn.cfg.SocketTimeout != 0 {
		t.Errorf("-1 disables it, got %v", conn.cfg.SocketTimeout)
	}
}

// Finding 7: tls=false (or secure=false) on an as400s:// DSN is an error, not a silent
// plaintext connection with the password in clear; the explicit opt-in is allowPlaintext.
func TestPlaintextDowngradeNeedsAnExplicitOptIn(t *testing.T) {
	for _, q := range []string{"tls=false", "secure=false", "tls=0"} {
		dsn := "as400s://U:P@host.example/LIB?" + q
		_, err := ParseDSN(dsn)
		if !errors.Is(err, ErrInvalidDSN) || !strings.Contains(err.Error(), "allowPlaintext") {
			t.Errorf("%s: %v, want an error naming allowPlaintext", q, err)
		}
		if err != nil && strings.Contains(err.Error(), ":P@") {
			t.Errorf("%s: the error leaks the DSN", q)
		}
		cfg, err := ParseDSN(dsn + "&allowPlaintext=true")
		if err != nil || cfg.UseTLS {
			t.Errorf("%s with allowPlaintext=true: %v %v", q, cfg, err)
		}
	}
	// A scheme that already says plaintext is explicit; TLS stays the as400s default.
	if cfg, err := ParseDSN("as400://U:P@host.example/LIB"); err != nil || cfg.UseTLS {
		t.Errorf("as400:// is the explicit plaintext scheme: %v %v", cfg, err)
	}
	if cfg, err := ParseDSN("as400s://U:P@host.example/LIB?tls=true"); err != nil || !cfg.UseTLS {
		t.Errorf("tls=true: %v %v", cfg, err)
	}
	if cfg, err := ParseDSN("as400://U:P@host.example/LIB?tls=true"); err != nil || !cfg.UseTLS {
		t.Errorf("tls=true upgrades a plain scheme: %v %v", cfg, err)
	}
}

// Finding 8: a minimum password level; a server that announces a lower one is refused
// before the password (or a substitute of it) is sent.
func TestMinPasswordLevelRefusesAServerDowngrade(t *testing.T) {
	// Each rig is a subtest: the signon port is fixed, and only a subtest's cleanup frees
	// it for the next rig (in v0.1.0 the second half always skipped on "address in use").
	t.Run("below the minimum", func(t *testing.T) {
		signon, database := ucStartRig(t, ucDefaultSignon(0), ucDefaultDB())
		db := ucOpenDB(t, ucDSN(database.port(), "&minPasswordLevel=3"))
		err := db.PingContext(ucContext(t))
		if err == nil || !errors.Is(err, ErrAuthentication) {
			t.Fatalf("a level 0 server under minPasswordLevel=3: %v", err)
		}
		signon.mu.Lock()
		defer signon.mu.Unlock()
		for _, r := range signon.records {
			if r.ReqRepID == RequestSignonInfo {
				t.Error("the password exchange was sent to a server below the minimum level")
			}
		}
	})
	if _, err := ParseDSN("as400s://U:P@h/L?minPasswordLevel=9"); err == nil {
		t.Error("minPasswordLevel above 4 accepted")
	}
	t.Run("at or above the minimum", func(t *testing.T) {
		_, database := ucStartRig(t, ucDefaultSignon(4), ucDefaultDB())
		db := ucOpenDB(t, ucDSN(database.port(), "&minPasswordLevel=3"))
		if err := db.PingContext(ucContext(t)); err != nil {
			t.Errorf("level 4 under minimum 3: %v", err)
		}
	})
}

// Finding 8: ResolvePort honours cancellation while it waits for the port mapper.
func TestResolvePortHonoursCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", ucMapperAddr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", ucMapperAddr, err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(10 * time.Second) // never answers
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(stallTimeout, cancel)
	within(t, "ResolvePort cancelled", 4*stallTimeout, func() {
		if _, err := ResolvePort(ctx, "127.0.0.1", "as-database"); err == nil {
			t.Error("ResolvePort succeeded against a mapper that never answers")
		}
	})
}

// Finding 8: no code formats a Go float as an SQL literal.
func TestNoSQLLiteralExpansion(t *testing.T) {
	for _, name := range []string{"expandSQLQuery", "sqlLiteralFromNamedValue"} {
		if funcExists(t, name) {
			t.Errorf("%s still exists: it formats values (floats included) into SQL text", name)
		}
	}
}
