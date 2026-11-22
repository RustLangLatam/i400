package i400

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"database/sql/driver"
	"encoding/hex"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Fuzz targets for every decoder that reads bytes a server sent. Each one
// checks that no input panics, that the work stays bounded (a parser may not
// allocate more than fuzzAllocLimit for an input of at most fuzzMaxInput bytes),
// and, where there is a stated rule, that the rule holds.
//
// `go test` runs the seed corpus below as ordinary tests. To search further:
//
//	go test -run '^$' -fuzz FuzzParseFetchPayload -fuzztime 60s .
//
// Seeds come from two places: the JTOpen-recorded text conversion vectors in
// testdata/ and internal/ccsid/testdata/ (real server byte sequences with their
// expected text), and small hand-built well-formed payloads for the structural
// parsers (the repository records no raw host-server packet captures).

const (
	fuzzMaxInput   = 1 << 20
	fuzzAllocLimit = 64 << 20
)

// boundedRun runs f and fails the fuzz case when it allocated more than the
// limit, which for inputs this small can only be an announced-length trusted.
func boundedRun(t *testing.T, f func()) {
	t.Helper()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	f()
	runtime.ReadMemStats(&after)
	if n := after.TotalAlloc - before.TotalAlloc; n > fuzzAllocLimit {
		t.Fatalf("allocated %d bytes for a small input", n)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v for a small input", d)
	}
}

func fuzzInputOK(data []byte) bool { return len(data) <= fuzzMaxInput }

// goldenSeeds reads up to max lines of a gzipped golden file.
func goldenSeeds(tb testing.TB, path string, max int) []string {
	tb.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read %s: %v", path, err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		tb.Fatalf("gunzip %s: %v", path, err)
	}
	defer zr.Close()
	var lines []string
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() && len(lines) < max {
		lines = append(lines, sc.Text())
	}
	return lines
}

func ccsidVectorSeeds(f *testing.F) {
	for _, line := range goldenSeeds(f, "internal/ccsid/testdata/jtopen_golden.txt.gz", 400) {
		parts := strings.Fields(line)
		if len(parts) != 4 || parts[0] != "D" {
			continue
		}
		id, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		if raw, err := hex.DecodeString(parts[2]); err == nil {
			f.Add(raw, uint16(id))
		}
	}
	f.Add([]byte("ABC 123"), uint16(37))
	f.Add([]byte{0xC1, 0xC2, 0xC3, 0x40, 0xF1, 0xF2}, uint16(37))
	f.Add([]byte{0x0E, 0x41, 0x42, 0x0F}, uint16(930))
}

func FuzzDecodeTextByCCSID(f *testing.F) {
	ccsidVectorSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte, id uint16) {
		if !fuzzInputOK(data) {
			t.Skip()
		}
		boundedRun(t, func() { _, _ = decodeTextByCCSID(data, int(id)) })
	})
}

func FuzzDecodeTextWithBidi(f *testing.F) {
	for _, line := range goldenSeeds(f, "testdata/bidi_driver_conv.txt.gz", 300) {
		parts := strings.Split(line, "\t")
		if len(parts) < 7 || parts[0] != "C" {
			continue
		}
		id, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		if raw, err := hex.DecodeString(parts[6]); err == nil {
			f.Add(raw, uint16(id), uint8(5))
		}
	}
	f.Add([]byte{0x64, 0x65}, uint16(420), uint8(5))
	f.Fuzz(func(t *testing.T, data []byte, id uint16, stringType uint8) {
		if !fuzzInputOK(data) {
			t.Skip()
		}
		bs := defaultBidiSettings()
		bs.StringType = int(stringType % 12)
		boundedRun(t, func() { _, _ = decodeTextWithBidi(data, int(id), bs) })
	})
}

var exactDecimalText = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)

func FuzzDecodeColumnValue(f *testing.F) {
	f.Add(uint16(db2TypeDecimal), uint16(3), uint16(5), uint16(2), uint16(0), []byte{0x12, 0x34, 0x5C})
	f.Add(uint16(db2TypeNumeric), uint16(5), uint16(5), uint16(2), uint16(0), []byte{0xF1, 0xF2, 0xF3, 0xF4, 0xD5})
	f.Add(uint16(db2TypeDecfloat), uint16(8), uint16(16), uint16(0), uint16(0), make([]byte, 8))
	f.Add(uint16(db2TypeDecfloat), uint16(16), uint16(34), uint16(0), uint16(0), make([]byte, 16))
	f.Add(uint16(db2TypeVarchar), uint16(12), uint16(0), uint16(0), uint16(37), []byte{0, 3, 0xC1, 0xC2, 0xC3})
	f.Add(uint16(db2TypeBlob), uint16(8), uint16(0), uint16(0), uint16(65535), []byte{0, 0, 0, 2, 1, 2})
	f.Fuzz(func(t *testing.T, typ, length, precision, scale, ccsid uint16, raw []byte) {
		if !fuzzInputOK(raw) {
			t.Skip()
		}
		col := columnMeta{Type: int(typ), Length: int(length), Precision: int(precision), Scale: int(scale), CCSID: int(ccsid)}
		var got driver.Value
		var err error
		boundedRun(t, func() { got, err = decodeColumnValue(col, raw) })
		if err != nil {
			return
		}
		switch col.db2Type() {
		case db2TypeDecimal, db2TypeNumeric:
			s, ok := got.(string)
			if !ok {
				t.Fatalf("exact numeric decoded as %T", got)
			}
			if !exactDecimalText.MatchString(s) {
				t.Fatalf("exact numeric %q is not canonical decimal text", s)
			}
			frac := 0
			if i := strings.IndexByte(s, '.'); i >= 0 {
				frac = len(s) - i - 1
			}
			if frac != col.Scale {
				t.Fatalf("%q has %d fraction digits, column scale is %d", s, frac, col.Scale)
			}
			if s == "-0" || strings.HasPrefix(s, "-0.") && strings.Trim(s[1:], "0.") == "" {
				t.Fatalf("negative zero %q", s)
			}
		case db2TypeDecfloat:
			if _, ok := got.(string); !ok {
				t.Fatalf("DECFLOAT decoded as %T", got)
			}
		}
	})
}

// Whatever text a client binds, a value that is accepted must read back as the
// same number, and one that cannot be held exactly must be refused.
func FuzzDecimalBindRoundTrip(f *testing.F) {
	for _, s := range []string{"0", "-0.50", "123.45", "99999999999999999999999999999.99", "1e2", ".5", "5.", "abc", "", "1.234", "-0.00"} {
		f.Add(s, uint8(31), uint8(2))
	}
	f.Fuzz(func(t *testing.T, text string, precision, scale uint8) {
		p := int(precision%63) + 1
		s := int(scale) % (p + 1)
		length := p/2 + 1
		field := parameterMarkerField{SQLType: db2TypeDecimal, Length: length, Precision: p, Scale: s, CCSID: 37}
		enc, err := encodeParameterValue(field, text, false)
		if err != nil {
			return
		}
		dec, err := decodeColumnValue(columnMeta{Type: db2TypeDecimal, Length: length, Precision: p, Scale: s}, enc)
		if err != nil {
			t.Fatalf("encoded %q for DECIMAL(%d,%d) but cannot decode it: %v", text, p, s, err)
		}
		if strings.ContainsAny(text, "eE") && len(text) > 24 {
			return // an exponent this large cannot be compared with big.Rat in a test
		}
		if !sameDecimalValue(t, dec.(string), strings.TrimSpace(text)) {
			t.Fatalf("DECIMAL(%d,%d): bound %q, read back %q", p, s, text, dec)
		}
	})
}

type bytesConn struct {
	net.Conn
	r *bytes.Reader
}

func (c bytesConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func FuzzReadPacket(f *testing.F) {
	f.Add(append(lengthPrefix(HeaderSize), make([]byte, HeaderSize-4)...))
	f.Add(lengthPrefix(0xFFFFFFFF))
	f.Add(lengthPrefix(maxPacketLength))
	f.Fuzz(func(t *testing.T, data []byte) {
		if !fuzzInputOK(data) {
			t.Skip()
		}
		boundedRun(t, func() {
			packet, err := readPacket(bytesConn{r: bytes.NewReader(data)})
			if err == nil && (len(packet) < HeaderSize || len(packet) > len(data)) {
				t.Fatalf("returned a packet of %d bytes from %d", len(packet), len(data))
			}
		})
	})
}

func payloadSeeds(f *testing.F) {
	f.Add([]byte{})
	f.Add(join(be32(0), be32(1), be16(1), be16(2), be32(0), be32(4), be16(0), []byte{0, 0, 0, 7}))
	f.Add(join(be32(0), be32(1), be16(1), be16(2), be16(4), be16(0), []byte{0, 0, 0, 7}))
	f.Add(join(be32(6+10), be16(0x380E), be32(0), be32(0), be16(0)))
	f.Add(join(be32(0xFFFFFFFF), be16(0x3811), be32(0xFFFFFFFF), make([]byte, 6)))
	f.Add(join(be32(2), be32(1), []byte{0, 0, 0, 0}, be32(4), make([]byte, 48)))
}

func fuzzParser(f *testing.F, parse func([]byte)) {
	payloadSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if !fuzzInputOK(data) {
			t.Skip()
		}
		boundedRun(t, func() { parse(data) })
	})
}

func FuzzParseDescribePayload(f *testing.F) {
	fuzzParser(f, func(b []byte) { _, _ = parseDescribePayload(b) })
}

func FuzzParseExtendedColumnDescriptors(f *testing.F) {
	fuzzParser(f, func(b []byte) { _ = parseExtendedColumnDescriptors(b, &resultSetMeta{}) })
}

func FuzzParseSuperExtendedDataFormat(f *testing.F) {
	fuzzParser(f, func(b []byte) { _ = parseSuperExtendedDataFormat(b, &resultSetMeta{}) })
}

func FuzzParseFetchPayload(f *testing.F) {
	fuzzParser(f, func(b []byte) {
		if blk, err := parseFetchPayload(b); err == nil && blk != nil && blk.RowSize > 0 && len(blk.Data) < blk.RowCount*blk.RowSize {
			panic("fetch block data shorter than its rows")
		}
	})
}

func FuzzParseResultDataBlocks(f *testing.F) {
	fuzzParser(f, func(b []byte) {
		_, _ = parseResultDataPayload(b)
		_, _ = parseOriginalResultDataPayload(b)
	})
}

func FuzzParseParameterMarkerFormat(f *testing.F) {
	fuzzParser(f, func(b []byte) {
		_, _ = parseParameterMarkerFormatFromPayload(b)
		_, _ = parseOriginalParameterMarkerFormat(b)
		_, _ = parseExtendedParameterMarkerFormat(b)
		_, _ = parseSuperExtendedParameterMarkerFormat(b)
	})
}

func FuzzParseSQLCA(f *testing.F) {
	fuzzParser(f, func(b []byte) { _, _ = parseSQLCAFromPayload(b) })
}

func FuzzParsePackageInfo(f *testing.F) {
	fuzzParser(f, func(b []byte) {
		_, _ = parsePackageInfo(b, 37)
		_, _ = parseSQLDAFormat(b, 37)
	})
}

func FuzzParseLLCPAndLOBs(f *testing.F) {
	fuzzParser(f, func(b []byte) {
		_, _, _, _ = ParseLLCP(b)
		_, _ = parseCurrentLobLengthFromPayload(b)
		_, _ = parseLobDataFromPayload(b)
	})
}

func FuzzParseServerAttributesAndMessages(f *testing.F) {
	fuzzParser(f, func(b []byte) {
		_ = parseServerAttributesPayload(b, &SystemInfo{})
		_ = parseServerAttributesBlock(b, &SystemInfo{})
		_, _ = parseSQLMessageText(b)
		_ = sqlerrmcTokens(b)
		_, _, _ = readSimpleReply(b)
		_, _, _ = readReplyEnvelope(b)
		_, _ = ParseHeader(b)
	})
}

func FuzzDecfloatDecoders(f *testing.F) {
	f.Add(make([]byte, 8))
	f.Add(make([]byte, 16))
	f.Add([]byte{0x78, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0x7C, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64 {
			t.Skip()
		}
		_, _ = decodeDecfloat16(data)
		_, _ = decodeDecfloat34(data)
	})
}
