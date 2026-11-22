package i400

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func TestMaxPacketBytesDefaultsAndValidates(t *testing.T) {
	cfg, err := ParseDSN("as400s://U:P@host.example/LIB")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.packetLimit(); got != maxPacketLength {
		t.Fatalf("default limit = %d, want %d", got, maxPacketLength)
	}
	cfg, err = ParseDSN("as400s://U:P@host.example/LIB?maxPacketBytes=1048576")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.packetLimit(); got != 1<<20 {
		t.Fatalf("limit = %d, want 1 MiB", got)
	}
	for _, bad := range []string{"-1", "abc", "1023", "2147483648", "1073741825"} {
		if _, err := ParseDSN("as400s://U:P@host.example/LIB?maxPacketBytes=" + bad); err == nil {
			t.Errorf("maxPacketBytes=%s accepted", bad)
		}
	}
	if _, err := ParseDSN("as400s://U:P@host.example/LIB?maxPacketBytes=1073741824"); err != nil {
		t.Errorf("maxPacketBytes at the hard cap refused: %v", err)
	}
}

// The limit applies to the connection dialHostServer returns, so every reply
// read on it is bounded by the configured value.
func TestDialedConnectionEnforcesMaxPacketBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], 1<<20)
		_, _ = c.Write(prefix[:])
		_, _ = c.Write(make([]byte, 100))
		_, _ = io.Copy(io.Discard, c) // hold the connection open until the client closes it
	}()
	host, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := net.LookupPort("tcp", portText)
	cfg := Config{Host: host, MaxPacketBytes: 4096}
	conn, err := dialHostServer(context.Background(), cfg, port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = readPacket(conn)
	requireWireError(t, err, "validate packet length")
}
