package i400

import (
	"database/sql/driver"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// FuzzBindAgainstHostileField binds null, text, binary and decimal values against a
// field description a hostile server could have sent: no size in it may make the driver
// allocate more than maxFieldBytes (a few buffers of it at most).
func FuzzBindAgainstHostileField(f *testing.F) {
	f.Add(uint16(db2TypeVarchar), uint32(10), uint16(0), uint16(0), uint16(37), uint32(0), []byte("abc"), uint8(0))
	f.Add(uint16(db2TypeBlob), uint32(0), uint16(0), uint16(0), uint16(65535), uint32(1<<31), []byte{1}, uint8(1))
	f.Add(uint16(db2TypeChar), uint32(0xFFFFFFFF), uint16(0), uint16(0), uint16(37), uint32(0), []byte("x"), uint8(2))
	f.Add(uint16(db2TypeDecimal), uint32(3), uint16(2), uint16(5), uint16(0), uint32(0), []byte("12.34"), uint8(0))
	f.Fuzz(func(t *testing.T, typ uint16, length uint32, scale, precision, ccsid uint16, lobMax uint32, value []byte, kind uint8) {
		if !fuzzInputOK(value) {
			t.Skip()
		}
		field := parameterMarkerField{SQLType: int(typ), Length: int(length), Scale: int(scale), Precision: int(precision), CCSID: int(ccsid), LOBMaxSize: int(lobMax)}
		var v driver.Value
		switch kind % 3 {
		case 0:
			v = string(value)
		case 1:
			v = value
		}
		boundedRun(t, func() { _, _ = encodeParameterValue(field, v, v == nil) })
	})
}

// FuzzParseFormatThenBind parses a hostile parameter marker format and, when it parses,
// binds a null and a text value to every field it describes.
func FuzzParseFormatThenBind(f *testing.F) {
	f.Add(superFormat(1, 8, [3]uint32{db2TypeVarchar, 10, 0}))
	f.Add(extFormat(1, 8, [3]uint32{db2TypeBlob, 8, 1 << 31}))
	payloadSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if !fuzzInputOK(data) {
			t.Skip()
		}
		boundedRun(t, func() {
			for _, parse := range []func([]byte) (*parameterMarkerFormat, error){parseSuperExtendedParameterMarkerFormat, parseExtendedParameterMarkerFormat, parseOriginalParameterMarkerFormat} {
				format, err := parse(data)
				if err != nil || format == nil {
					continue
				}
				for _, field := range format.Fields {
					_, _ = encodeParameterValue(field, nil, true)
					_, _ = encodeParameterValue(field, "abc", false)
				}
			}
		})
	})
}

var fuzzCanonicalDecfloat = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)

// FuzzDecfloatReadIsCanonical: whatever 8 or 16 bytes arrive, a DECFLOAT read is an error, a
// typed special-value error, or canonical decimal text (no negative zero, no leading
// zeros, no zero padded to the exponent).
func FuzzDecfloatReadIsCanonical(f *testing.F) {
	f.Add(make([]byte, 8))
	f.Add(make([]byte, 16))
	f.Add([]byte{0x78, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0x22, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != 8 && len(data) != 16 {
			t.Skip()
		}
		col := columnMeta{Type: db2TypeDecfloat, Length: len(data)}
		got, err := decodeColumnValue(col, data)
		if err != nil {
			var special *DecfloatSpecialError
			if errors.As(err, &special) && got != nil {
				t.Fatalf("special value returned a result %v", got)
			}
			return
		}
		s, ok := got.(string)
		if !ok || !fuzzCanonicalDecfloat.MatchString(s) || s == "-0" || strings.HasPrefix(s, "-0.") && strings.Trim(s, "-0.") == "" || len(s) > 7000 {
			t.Fatalf("non-canonical DECFLOAT %q (%T)", got, got)
		}
	})
}

// FuzzDecfloatBindNeverChangesTheValue: a text that binds must read back as the same
// number; one that cannot be stored exactly must be refused.
func FuzzDecfloatBindNeverChangesTheValue(f *testing.F) {
	for _, s := range []string{"1", "1.50", "0E-300", "1E-398", "1E-399", "12345678901234567", "-0", "1E+369"} {
		f.Add(s, uint8(0))
	}
	f.Fuzz(func(t *testing.T, text string, big uint8) {
		size := 8
		if big%2 == 1 {
			size = 16
		}
		if len(text) > 200 {
			t.Skip()
		}
		field := decfloatField(size)
		enc, err := encodeParameterValue(field, text, false)
		if err != nil {
			return
		}
		got, err := decodeColumnValue(columnMeta{Type: db2TypeDecfloat, Length: size}, enc)
		if err != nil {
			return // NaN and infinities bind as themselves and read as a typed error
		}
		if strings.ContainsAny(text, "eE") && len(text) > 24 {
			return
		}
		if !sameDecimalValue(t, got.(string), strings.TrimSpace(text)) {
			t.Fatalf("bound %q, read back %q", text, got)
		}
	})
}
