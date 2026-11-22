package i400

import (
	"testing"
)

// Hardening contract (review finding 1): a parameter-marker format a server sends is
// validated when it is parsed, and a field the driver is asked to bind can never make it
// allocate more than maxFieldBytes, whatever the format says.

// superFormat builds a 0x3812-style super extended parameter marker format with one
// entry per (sqlType, length, lobMax).
func superFormat(count uint32, recordSize uint32, entries ...[3]uint32) []byte {
	out := join(be32(0), be32(count), be32(0), be32(recordSize))
	for _, e := range entries {
		entry := make([]byte, 48)
		copy(entry[2:4], be16(uint16(e[0])))
		copy(entry[4:8], be32(e[1]))
		copy(entry[26:30], be32(e[2]))
		out = append(out, entry...)
	}
	return out
}

func extFormat(count uint32, recordSize uint32, entries ...[3]uint32) []byte {
	out := join(be32(0), be32(count), be32(0), be32(recordSize))
	for _, e := range entries {
		entry := make([]byte, 64)
		copy(entry[2:4], be16(uint16(e[0])))
		copy(entry[4:8], be32(e[1]))
		copy(entry[26:30], be32(e[2]))
		out = append(out, entry...)
	}
	return out
}

func TestMarkerFormatsRefuseHostileSizes(t *testing.T) {
	const huge = 0xFFFFFFFF
	// Built before the measurement: the payloads are the test's, not the parser's.
	bigSuper := join(be32(0), be32(maxColumns+1), be32(0), be32(0), make([]byte, 48*(maxColumns+1)))
	bigExt := join(be32(0), be32(maxColumns+1), be32(0), be32(0), make([]byte, 64*(maxColumns+1)))
	cases := map[string]func() error{
		"super: field length 4G": func() error {
			_, err := parseSuperExtendedParameterMarkerFormat(superFormat(1, 8, [3]uint32{db2TypeVarchar, huge, 0}))
			return err
		},
		"super: field length above the cap": func() error {
			_, err := parseSuperExtendedParameterMarkerFormat(superFormat(1, 8, [3]uint32{db2TypeChar, maxFieldBytes + 1, 0}))
			return err
		},
		"super: record size 4G": func() error {
			_, err := parseSuperExtendedParameterMarkerFormat(superFormat(1, huge, [3]uint32{db2TypeInteger, 4, 0}))
			return err
		},
		"super: fields that together exceed the packet limit": func() error {
			var e [][3]uint32
			for i := 0; i < 8; i++ {
				e = append(e, [3]uint32{db2TypeChar, maxFieldBytes, 0})
			}
			_, err := parseSuperExtendedParameterMarkerFormat(superFormat(8, 8, e...))
			return err
		},
		"super: count above maxColumns": func() error {
			_, err := parseSuperExtendedParameterMarkerFormat(bigSuper)
			return err
		},
		"extended: field length 4G": func() error {
			_, err := parseExtendedParameterMarkerFormat(extFormat(1, 8, [3]uint32{db2TypeVarchar, huge, 0}))
			return err
		},
		"extended: count above maxColumns": func() error {
			_, err := parseExtendedParameterMarkerFormat(bigExt)
			return err
		},
	}
	for name, f := range cases {
		requireRefusedCheaply(t, name, f)
	}
	// A well-formed format still parses, with a LOB whose declared maximum is large.
	f, err := parseSuperExtendedParameterMarkerFormat(superFormat(2, 12, [3]uint32{db2TypeInteger, 4, 0}, [3]uint32{db2TypeBlob, 8, 1 << 31}))
	if err != nil || len(f.Fields) != 2 {
		t.Fatalf("well-formed format: %v %v", f, err)
	}
}

// Binding against a field the server described with a lying size: every path refuses
// before allocating (null, text, binary and inline LOB).
func TestBindRefusesLyingFieldSizes(t *testing.T) {
	for _, typ := range []int{db2TypeChar, db2TypeVarchar, db2TypeBinary, db2TypeVarbinary, db2TypeInteger, db2TypeBlob, db2TypeClob, db2TypeDecimal} {
		for name, field := range map[string]parameterMarkerField{
			"length 2G":      {SQLType: typ, Length: 1 << 31, CCSID: 37},
			"length max-int": {SQLType: typ, Length: int(^uint(0) >> 1), CCSID: 37},
			"negative":       {SQLType: typ, Length: -5, CCSID: 37},
			"lob max 2G":     {SQLType: typ, Length: 0, LOBMaxSize: 1 << 31, CCSID: 37},
		} {
			for _, v := range []any{nil, "abc", []byte{1, 2, 3}} {
				if name == "lob max 2G" && (v == nil || (typ != db2TypeBlob && typ != db2TypeClob)) {
					continue // only an inline LOB value is sized from LOBMaxSize
				}
				requireRefusedCheaply(t, name, func() error {
					_, err := encodeParameterValue(field, v, v == nil)
					return err
				})
			}
		}
	}
}

func TestLyingLengthsAreErrorsNotClamps(t *testing.T) {
	// VARBINARY value announcing 100 bytes with 3 present.
	col := columnMeta{Type: db2TypeVarbinary, Length: 5}
	if got, err := decodeColumnValue(col, []byte{0, 100, 1, 2, 3}); err == nil {
		t.Errorf("VARBINARY with a lying length decoded as %v", got)
	}
	// LOB locator data announcing more than it carries.
	payload := join(be32(6+6+3), be16(CodePointLOBLocatorData), be16(0), be32(100), []byte{1, 2, 3})
	if got, err := parseLobDataFromPayload(payload); err == nil {
		t.Errorf("LOB data with a lying length parsed as %v", got)
	}
}
