package i400

import (
	"fmt"
	"strings"
	"testing"
)

// Hardening contract (see HARDENING.md): DECIMAL, NUMERIC and DECFLOAT values
// cross the driver as exact decimal strings in both directions. A float is never
// produced for them, a bind that would change the stored value is an error, and
// a row whose bytes do not match the column description is an error rather than
// a guessed value.

// packedBytes builds a packed decimal from its digit string and sign nibble.
func packedBytes(digits string, sign byte) []byte {
	if len(digits)%2 == 0 {
		digits = "0" + digits
	}
	out := make([]byte, 0, len(digits)/2+1)
	nibbles := make([]byte, 0, len(digits)+1)
	for _, c := range digits {
		nibbles = append(nibbles, byte(c-'0'))
	}
	nibbles = append(nibbles, sign)
	for i := 0; i < len(nibbles); i += 2 {
		out = append(out, nibbles[i]<<4|nibbles[i+1])
	}
	return out
}

// zonedBytes builds a zoned decimal; the last byte carries the sign in its zone.
func zonedBytes(digits string, sign byte) []byte {
	out := make([]byte, len(digits))
	for i, c := range digits {
		out[i] = 0xF0 | byte(c-'0')
	}
	out[len(out)-1] = sign<<4 | (out[len(out)-1] & 0x0F)
	return out
}

func decimalCol(typ, precision, scale, length int) columnMeta {
	return columnMeta{Type: typ, Precision: precision, Scale: scale, Length: length}
}

func TestExactNumericDecodesToStringNeverFloat(t *testing.T) {
	nines29 := strings.Repeat("9", 29)
	cases := []struct {
		name string
		col  columnMeta
		raw  []byte
		want string
	}{
		{"packed 31,2 max", decimalCol(db2TypeDecimal, 31, 2, 16), packedBytes(nines29+"99", 0x0C), nines29 + ".99"},
		{"packed 31,2 spec value", decimalCol(db2TypeDecimal, 31, 2, 16), packedBytes("1234567890123456789012345678901", 0x0C), "12345678901234567890123456789.01"},
		{"packed 63,0", decimalCol(db2TypeDecimal, 63, 0, 32), packedBytes(strings.Repeat("9", 63), 0x0D), "-" + strings.Repeat("9", 63)},
		{"packed 63,63", decimalCol(db2TypeDecimal, 63, 63, 32), packedBytes(strings.Repeat("0", 62)+"1", 0x0C), "0." + strings.Repeat("0", 62) + "1"},
		{"packed 2,2 negative", decimalCol(db2TypeDecimal, 2, 2, 2), packedBytes("50", 0x0D), "-0.50"},
		{"packed 5,2 negative zero is zero", decimalCol(db2TypeDecimal, 5, 2, 3), packedBytes("00000", 0x0D), "0.00"},
		{"packed 5,2 alternate positive sign", decimalCol(db2TypeDecimal, 5, 2, 3), packedBytes("12345", 0x0F), "123.45"},
		{"packed 16 digits beyond float64", decimalCol(db2TypeDecimal, 18, 2, 10), packedBytes("999999999999999999", 0x0C), "9999999999999999.99"},
		{"zoned 7,2 negative", decimalCol(db2TypeNumeric, 7, 2, 7), zonedBytes("0012345", 0x0D), "-123.45"},
		{"zoned 5,0", decimalCol(db2TypeNumeric, 5, 0, 5), zonedBytes("00042", 0x0F), "42"},
		{"zoned 5,2 negative zero is zero", decimalCol(db2TypeNumeric, 5, 2, 5), zonedBytes("00000", 0x0D), "0.00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeColumnValue(tc.col, tc.raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			s, ok := got.(string)
			if !ok {
				t.Fatalf("decoded %T, want string (exact decimal text)", got)
			}
			if s != tc.want {
				t.Fatalf("decoded %q, want %q", s, tc.want)
			}
		})
	}
}

func TestDecfloatDecodesToStringNeverFloat(t *testing.T) {
	for _, size := range []int{8, 16} {
		col := columnMeta{Type: db2TypeDecfloat, Length: size, Precision: map[int]int{8: 16, 16: 34}[size]}
		raw := make([]byte, size)
		// the all-zero pattern is the value 0 with the smallest exponent bias; any
		// valid pattern must still come back as text.
		got, err := decodeColumnValue(col, raw)
		if err != nil {
			t.Fatalf("DECFLOAT(%d): %v", col.Precision, err)
		}
		if _, ok := got.(string); !ok {
			t.Fatalf("DECFLOAT(%d) decoded %T, want string", col.Precision, got)
		}
	}
}

func TestExactNumericRefusesRowsThatDoNotMatchTheColumn(t *testing.T) {
	cases := []struct {
		name string
		col  columnMeta
		raw  []byte
	}{
		{"packed bad digit nibble", decimalCol(db2TypeDecimal, 5, 2, 3), []byte{0x1A, 0x34, 0x5C}},
		{"packed bad sign nibble", decimalCol(db2TypeDecimal, 5, 2, 3), []byte{0x12, 0x34, 0x59}},
		{"packed too short for precision", decimalCol(db2TypeDecimal, 5, 2, 3), []byte{0x5C}},
		{"packed longer than precision would drop high digits", decimalCol(db2TypeDecimal, 5, 2, 5), []byte{0x99, 0x99, 0x12, 0x34, 0x5C}},
		{"packed empty", decimalCol(db2TypeDecimal, 5, 2, 0), nil},
		{"packed row truncated below column length", decimalCol(db2TypeDecimal, 9, 2, 5), []byte{0x00, 0x12, 0x3C}},
		{"packed precision zero", decimalCol(db2TypeDecimal, 0, 0, 1), []byte{0x0C}},
		{"packed precision above 63", decimalCol(db2TypeDecimal, 64, 0, 33), append(make([]byte, 32), 0x0C)},
		{"packed scale above precision", decimalCol(db2TypeDecimal, 5, 6, 3), []byte{0x12, 0x34, 0x5C}},
		{"packed negative precision", decimalCol(db2TypeDecimal, -1, 0, 3), []byte{0x12, 0x34, 0x5C}},
		{"zoned bad digit nibble", decimalCol(db2TypeNumeric, 3, 0, 3), []byte{0xF1, 0xFA, 0xF3}},
		{"zoned bad sign zone", decimalCol(db2TypeNumeric, 3, 0, 3), []byte{0xF1, 0xF2, 0x33}},
		{"zoned wrong length", decimalCol(db2TypeNumeric, 5, 0, 5), []byte{0xF1, 0xF2, 0xFC}},
		{"zoned empty", decimalCol(db2TypeNumeric, 5, 0, 0), nil},
		{"zoned scale above precision", decimalCol(db2TypeNumeric, 3, 4, 3), []byte{0xF1, 0xF2, 0xF3}},
		{"decfloat odd length", columnMeta{Type: db2TypeDecfloat, Length: 12}, make([]byte, 12)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeColumnValue(tc.col, tc.raw)
			if err == nil {
				t.Fatalf("decoded %#v, want an error", got)
			}
		})
	}
}

func exactFields() map[string]parameterMarkerField {
	return map[string]parameterMarkerField{
		"DECIMAL":  {SQLType: db2TypeDecimal, Length: 3, Precision: 5, Scale: 2, CCSID: 37},
		"NUMERIC":  {SQLType: db2TypeNumeric, Length: 5, Precision: 5, Scale: 2, CCSID: 37},
		"DECFLOAT": {SQLType: db2TypeDecfloat, Length: 8, Precision: 16, CCSID: 1208},
	}
}

func TestExactNumericBindRefusesBinaryFloatsAndBooleans(t *testing.T) {
	for name, field := range exactFields() {
		for _, v := range []any{float64(2.5), float64(0.1), true, false} {
			t.Run(fmt.Sprintf("%s %T %v", name, v, v), func(t *testing.T) {
				if got, err := encodeParameterValue(field, v, false); err == nil {
					t.Fatalf("encoded %#v to % x, want an error: a binary float or bool is not an exact decimal", v, got)
				}
			})
		}
	}
}

func TestExactNumericBindRefusesWhatWouldChangeTheValue(t *testing.T) {
	fixed := []string{"DECIMAL", "NUMERIC"}
	for _, name := range fixed {
		field := exactFields()[name]
		for _, v := range []string{"123.456", "2.279", "0.135", "-0.001", "1e-400", "1.239"} {
			if got, err := encodeParameterValue(field, v, false); err == nil {
				t.Errorf("%s encode(%q) = % x, want an error: fraction digits beyond the scale would be dropped", name, v, got)
			}
		}
		// Extra fraction digits that are all zero change nothing, so they bind.
		for _, v := range []string{"1.500", "-1.5000000", "1.0e0"} {
			if _, err := encodeParameterValue(field, v, false); err != nil {
				t.Errorf("%s encode(%q) error = %v, want exact bind", name, v, err)
			}
		}
	}
}

func TestExactNumericBindErrorsDoNotEchoTheValue(t *testing.T) {
	secret := "hunter2-4242"
	for name, field := range exactFields() {
		for _, v := range []any{secret, "1" + secret, secret + ".5"} {
			_, err := encodeParameterValue(field, v, false)
			if err == nil {
				t.Fatalf("%s: junk bind %q accepted", name, v)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: bind error echoes the bound value: %v", name, err)
			}
		}
	}
	_, err := encodeParameterValue(exactFields()["DECIMAL"], "99999999999999999999", false)
	if err == nil || strings.Contains(err.Error(), "99999999999999999999") {
		t.Errorf("overflow error = %v, want an error that does not echo the value", err)
	}
}

func TestExactNumericScanTypeIsString(t *testing.T) {
	for _, typ := range []int{db2TypeDecimal, db2TypeNumeric, db2TypeDecfloat} {
		if got := columnScanType(columnMeta{Type: typ}); got.Kind().String() != "string" {
			t.Errorf("ScanType for type %d = %v, want string", typ, got)
		}
	}
}

func TestExactNumericBindAcceptsExactTextIntegersAndBytes(t *testing.T) {
	for name, field := range exactFields() {
		for _, v := range []any{"12.5", " -12.5 ", []byte("7"), int64(42), int64(-7)} {
			if _, err := encodeParameterValue(field, v, false); err != nil {
				t.Errorf("%s encode(%#v) error = %v", name, v, err)
			}
		}
	}
}
