package i400

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func ResolvePort(ctx context.Context, host, service string) (int, error) {
	if strings.TrimSpace(host) == "" {
		return 0, fmt.Errorf("%w: host is required", ErrConnection)
	}
	if strings.TrimSpace(service) == "" {
		return 0, fmt.Errorf("%w: service is required", ErrConnection)
	}

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "449"))
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	// A cancelled context must end a read that is waiting for the mapper.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if _, err := io.WriteString(conn, service); err != nil {
		return 0, err
	}

	var prefix [1]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return 0, err
	}
	if prefix[0] != '+' {
		return 0, fmt.Errorf("unexpected port mapper reply: %q", prefix[0])
	}

	var portBuf [4]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return 0, err
	}
	port := int(binary.BigEndian.Uint32(portBuf[:]))
	if port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid port mapper reply: %d", port)
	}
	return port, nil
}
