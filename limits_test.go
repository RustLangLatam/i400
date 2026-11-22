package i400

import (
	"bytes"
	"database/sql/driver"
	"encoding/binary"
	"net"
	"runtime"
	"testing"
	"time"
)

// Hardening contract: every length or count read from the wire is checked
// against what the peer actually sent (and against a hard cap) before anything
// is allocated or looped over, so a hostile server cannot make the client
// allocate gigabytes or spin for billions of iterations with a few bytes.

// maxHostileAlloc is how much a parser may allocate while refusing a hostile
// header. Far below what the announced counts would need (gigabytes).
const maxHostileAlloc = 4 << 20

func allocatedBytes(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func be16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }

func join(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func requireRefusedCheaply(t *testing.T, name string, f func() error) {
	t.Helper()
	var err error
	start := time.Now()
	alloc := allocatedBytes(func() { err = f() })
	if err == nil {
		t.Errorf("%s: hostile input accepted", name)
	}
	if alloc > maxHostileAlloc {
		t.Errorf("%s: allocated %d bytes refusing a few bytes of input", name, alloc)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("%s: took %v to refuse a few bytes of input", name, d)
	}
}

func TestDescribeParsersRefuseHostileCounts(t *testing.T) {
	requireRefusedCheaply(t, "extended column descriptors, 4G columns", func() error {
		return parseExtendedColumnDescriptors(join(be32(0xFFFFFFFF), make([]byte, 6)), &resultSetMeta{})
	})
	requireRefusedCheaply(t, "extended column descriptors, more columns than the cap", func() error {
		return parseExtendedColumnDescriptors(join(be32(maxColumns+1), make([]byte, 6)), &resultSetMeta{})
	})
	requireRefusedCheaply(t, "super extended data format, 4G fields", func() error {
		header := join(be32(0), be32(0xFFFFFFFF), []byte{0, 0, 0, 0}, be32(0))
		return parseSuperExtendedDataFormat(header, &resultSetMeta{})
	})
	requireRefusedCheaply(t, "super extended data format, more fields than the cap", func() error {
		header := join(be32(0), be32(maxColumns+1), []byte{0, 0, 0, 0}, be32(0))
		return parseSuperExtendedDataFormat(header, &resultSetMeta{})
	})
}

func TestResultDataParsersRefuseHostileShapes(t *testing.T) {
	// 0x380E header: token, rowCount, columnCount, indicatorSize, reserved, rowSize.
	ext := func(rows uint32, cols, ind uint16, rowSize uint32) []byte {
		return join(be32(0), be32(rows), be16(cols), be16(ind), be32(0), be32(rowSize))
	}
	// 0x3806 header: token, rowCount, columnCount, indicatorSize, rowSize(16 bit).
	orig := func(rows uint32, cols, ind, rowSize uint16) []byte {
		return join(be32(0), be32(rows), be16(cols), be16(ind), be16(rowSize))
	}
	cases := map[string]func() error{
		"4G rows x 64K columns, no data": func() error {
			_, err := parseResultDataPayload(ext(0xFFFFFFFF, 0xFFFF, 2, 0xFFFFFFFF))
			return err
		},
		"4G rows, indicator size 0 (no bytes needed, would loop for ever)": func() error {
			_, err := parseResultDataPayload(ext(0xFFFFFFFF, 0xFFFF, 0, 0))
			return err
		},
		"4G rows, row size 0, indicator size 0": func() error {
			_, err := parseResultDataPayload(ext(0xFFFFFFFF, 1, 0, 0))
			return err
		},
		"rows x row size overflows 32 bits": func() error {
			_, err := parseResultDataPayload(ext(0x10001, 1, 0, 0x10000))
			return err
		},
		"original format, 4G rows": func() error {
			_, err := parseOriginalResultDataPayload(orig(0xFFFFFFFF, 0xFFFF, 0, 0xFFFF))
			return err
		},
		"more rows than the data holds": func() error {
			_, err := parseResultDataPayload(join(ext(1000, 1, 2, 8), make([]byte, 100)))
			return err
		},
	}
	for name, f := range cases {
		requireRefusedCheaply(t, name, f)
	}
}

func TestResultDataParserStillReadsAWellFormedBlock(t *testing.T) {
	rows, cols := uint32(3), uint16(2)
	payload := ext380E(rows, cols, 2, 8)
	for r := uint32(0); r < rows; r++ {
		for c := uint16(0); c < cols; c++ {
			ind := uint16(0)
			if r == 1 && c == 1 {
				ind = 0xFFFF
			}
			payload = append(payload, be16(ind)...)
		}
	}
	payload = append(payload, make([]byte, int(rows)*8)...)
	block, err := parseResultDataPayload(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if block.RowCount != 3 || block.ColumnCount != 2 || len(block.Data) != 24 || !block.Nulls[3] || block.Nulls[0] {
		t.Fatalf("unexpected block %+v", block)
	}
}

func ext380E(rows uint32, cols, ind uint16, rowSize uint32) []byte {
	return join(be32(0), be32(rows), be16(cols), be16(ind), be32(0), be32(rowSize))
}

// A block whose column count differs from the described columns used to index
// the null bitmap out of range (a panic on hostile input).
func TestDecodeCurrentRowRefusesABlockThatDoesNotMatchTheDescription(t *testing.T) {
	rows := &queryRows{
		meta:  &resultSetMeta{columns: []columnMeta{{Type: db2TypeInteger, Length: 4}, {Type: db2TypeInteger, Length: 4}, {Type: db2TypeInteger, Length: 4}}, RowSize: 12},
		block: &fetchBlock{RowCount: 1, ColumnCount: 1, IndicatorSize: 2, RowSize: 12, Nulls: make([]bool, 1), Data: make([]byte, 12)},
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	if err := rows.decodeCurrentRow(make([]driver.Value, 3)); err == nil {
		t.Fatal("decoded a row from a block with a different column count")
	}
}

type packetConn struct {
	net.Conn
	limit uint32
}

func (c packetConn) maxPacketBytes() uint32 { return c.limit }

func TestReadPacketUsesTheConnectionsLimit(t *testing.T) {
	conn := packetConn{Conn: feedPacket(t, lengthPrefix(2048), nil), limit: 1024}
	_, err := readPacket(conn)
	requireWireError(t, err, "validate packet length")

	conn = packetConn{Conn: feedPacket(t, lengthPrefix(1024), make([]byte, 1020)), limit: 1024}
	if _, err := readPacket(conn); err != nil {
		t.Fatalf("a packet at the limit must be read: %v", err)
	}
}

func TestDefaultPacketLimitIsFarBelowAGigabyte(t *testing.T) {
	if maxPacketLength > 256<<20 {
		t.Fatalf("default packet cap is %d bytes, want 256 MiB or less", maxPacketLength)
	}
	if hardMaxPacketLength < maxPacketLength {
		t.Fatal("hard cap below default")
	}
}

// The reader must grow with the bytes the peer actually sends, not with the
// length it announces.
func TestReadPacketDoesNotAllocateWhatThePeerOnlyAnnounces(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = client.Write(lengthPrefix(maxPacketLength))
		_, _ = client.Write(make([]byte, 100))
		_ = client.Close()
	}()
	var err error
	alloc := allocatedBytes(func() { _, err = readPacket(server) })
	if err == nil {
		t.Fatal("truncated packet accepted")
	}
	if alloc > maxHostileAlloc {
		t.Fatalf("allocated %d bytes for a packet of which 100 arrived", alloc)
	}
	requireWireError(t, err, "read packet body")
}
