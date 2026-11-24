package i400

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// A51: the PUB400 round 4 capture (2026-11-24) measured the indicators the
// host sends. -2 (FFFE) comes with SQLCODE +331 for a value it nulled on a data
// mapping error, -1 (FFFF) for a stored NULL. The buffer below is built the way
// the host sent it: 2-byte indicators, row 1 = (ID 0, C -2, N -1).
func TestRound4MeasuredIndicatorsReadAsNull(t *testing.T) {
	indicators := []byte{0x00, 0x00, 0xFF, 0xFE, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	data := make([]byte, 2*4)
	block, err := parseOriginalResultDataPayload(udOriginalPayload(2, 3, 2, 4, indicators, data))
	if err != nil {
		t.Fatalf("parseOriginalResultDataPayload() error = %v", err)
	}
	want := []bool{false, true, true, false, false, false}
	for i, w := range want {
		if block.Nulls[i] != w {
			t.Fatalf("Nulls[%d] = %v, want %v (all %v)", i, block.Nulls[i], w, block.Nulls)
		}
	}
}

// F05: the +331 warning of that fetch is on the connection, so a caller can
// tell a mapping NULL from a stored NULL (-1 carries no warning).
func TestRound4Warning331IsRecorded(t *testing.T) {
	c := &Conn{}
	if err := c.checkReply(context.Background(), 0, "fetch", replyEnvelope{RCClass: 1, RCCode: 331}, nil); err != nil {
		t.Fatalf("checkReply() error = %v", err)
	}
	w := c.Warnings()
	if w == nil || w.Code != 331 {
		t.Fatalf("Warnings() = %+v, want code 331", w)
	}
}

// F05: both refusals share one sentinel.
func TestParameterTooLongSentinel(t *testing.T) {
	_, errBin := encodeFixedBinaryParameter([]byte{1, 2, 3, 4, 5}, udField(db2TypeBinary, 4, 65535))
	_, errVar := encodeVarbinaryParameter([]byte{1, 2, 3, 4, 5}, udField(db2TypeVarbinary, 6, 65535))
	for name, err := range map[string]error{"BINARY": errBin, "VARBINARY": errVar} {
		if !errors.Is(err, ErrParameterTooLong) {
			t.Fatalf("%s error = %v, want ErrParameterTooLong", name, err)
		}
	}
}

// F07: the marker lengths measured on PUB400. BINARY(4) reports 4 and
// VARBINARY(4) reports 6 (n+2). 4 bytes round-trip, 5 bytes are refused.
func TestRound4MarkerLengths(t *testing.T) {
	four := []byte{1, 2, 3, 4}
	got, err := encodeFixedBinaryParameter(four, udField(db2TypeBinary, 4, 65535))
	if err != nil || !bytes.Equal(got, four) {
		t.Fatalf("BINARY(4) with 4 bytes = % X, %v", got, err)
	}
	got, err = encodeVarbinaryParameter(four, udField(db2TypeVarbinary, 6, 65535))
	if err != nil || !bytes.Equal(got, []byte{0, 4, 1, 2, 3, 4}) {
		t.Fatalf("VARBINARY(4) with 4 bytes = % X, %v", got, err)
	}
	five := []byte{1, 2, 3, 4, 5}
	if _, err := encodeFixedBinaryParameter(five, udField(db2TypeBinary, 4, 65535)); err == nil {
		t.Fatal("BINARY(4) with 5 bytes: error = nil")
	}
	if _, err := encodeVarbinaryParameter(five, udField(db2TypeVarbinary, 6, 65535)); err == nil {
		t.Fatal("VARBINARY(4) with 5 bytes: error = nil")
	}
}
