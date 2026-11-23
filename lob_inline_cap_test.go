package i400

import (
	"database/sql/driver"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// v0.1.1 finding 4: a LOB sent inline (no input locator) is capped, and going over the cap
// is a clear, typed error (ErrInlineLOBTooLarge) that names the limit, before any
// allocation sized from the server's declared maximum.
func TestInlineLOBCapIsAClearTypedError(t *testing.T) {
	limit := strconv.Itoa(maxInlineLOBBytes)
	cases := map[string]struct {
		field parameterMarkerField
		value driver.Value
	}{
		"declared maximum above the cap": {
			field: parameterMarkerField{SQLType: db2TypeBlob, LOBMaxSize: maxInlineLOBBytes + 1, CCSID: 65535},
			value: []byte("x"),
		},
		"declared maximum of 2 GiB": {
			field: parameterMarkerField{SQLType: db2TypeClob, LOBMaxSize: 1<<31 - 1, CCSID: 37},
			value: "x",
		},
		"value larger than the field": {
			field: parameterMarkerField{SQLType: db2TypeBlob, LOBMaxSize: 8, CCSID: 65535},
			value: []byte("123456789"),
		},
	}
	for name, c := range cases {
		_, err := encodeInlineLOBParameterValue(c.field, c.value, true, false)
		if !errors.Is(err, ErrInlineLOBTooLarge) {
			t.Errorf("%s: err = %v, want ErrInlineLOBTooLarge", name, err)
			continue
		}
		if name != "value larger than the field" && !strings.Contains(err.Error(), limit) {
			t.Errorf("%s: the error does not name the %s byte cap: %v", name, limit, err)
		}
	}
	// At the cap the value is accepted.
	field := parameterMarkerField{SQLType: db2TypeBlob, LOBMaxSize: 16, CCSID: 65535}
	if _, err := encodeInlineLOBParameterValue(field, []byte("0123456789abcdef"), true, false); err != nil {
		t.Errorf("a value that fits: %v", err)
	}
	if maxInlineLOBBytes != maxFieldBytes-4 {
		t.Errorf("maxInlineLOBBytes = %d, want the field cap minus the length prefix", maxInlineLOBBytes)
	}
}
