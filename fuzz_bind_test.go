package i400

import (
	"database/sql/driver"
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
