package i400

import (
	"errors"
	"strings"
	"testing"
)

// Review finding 5: DECFLOAT binds never change the value, and reads are canonical.

func decfloatField(size int) parameterMarkerField {
	p := 16
	if size == 16 {
		p = 34
	}
	return parameterMarkerField{SQLType: db2TypeDecfloat, Length: size, Precision: p, CCSID: 1208}
}

func TestDecfloatBindRefusesWhatWouldChangeTheValue(t *testing.T) {
	for _, size := range []int{8, 16} {
		field := decfloatField(size)
		maxDigits := 16
		if size == 16 {
			maxDigits = 34
		}
		refused := []string{
			"1E-10000",                             // underflow: would be stored as zero
			"1E-10000000000",                       // exponent far outside int range of digits
			"-1E-99999",                            // negative underflow
			"1E+10000",                             // overflow
			"1E+10000000000",                       // overflow, huge exponent
			strings.Repeat("9", maxDigits+1),       // one digit too many, the last is not zero
			"0." + strings.Repeat("0", 6200) + "1", // below the smallest exponent
			"1" + strings.Repeat("0", maxDigits+5) + "1", // trailing non-zero digit lost
		}
		for _, v := range refused {
			if got, err := encodeParameterValue(field, v, false); err == nil {
				t.Errorf("size %d: %.40q encoded to % x, want an error", size, v, got)
			}
		}
		accepted := []string{
			"0", "-0", "0E-10000", "0E+10000", "1", "1.50", "123456789012345", "9" + strings.Repeat("0", maxDigits-1), "1E+5",
			"1" + strings.Repeat("0", maxDigits+3), // trailing zeros beyond the precision lose nothing
		}
		for _, v := range accepted {
			if _, err := encodeParameterValue(field, v, false); err != nil {
				t.Errorf("size %d: %.40q refused: %v", size, v, err)
			}
		}
	}
	// The smallest exponent edge: 1E-398 is representable in DECFLOAT(16), 1E-399 is not.
	if _, err := encodeParameterValue(decfloatField(8), "1E-398", false); err != nil {
		t.Errorf("1E-398: %v", err)
	}
	if _, err := encodeParameterValue(decfloatField(8), "1E-399", false); err == nil {
		t.Error("1E-399 accepted")
	}
}

func TestDecfloatReadIsCanonical(t *testing.T) {
	for _, size := range []int{8, 16} {
		field := decfloatField(size)
		col := columnMeta{Type: db2TypeDecfloat, Length: size, Precision: field.Precision}
		cases := map[string]string{
			"0":         "0",
			"-0":        "0", // one spelling of zero, whatever the sign bit
			"0E+300":    "0", // not 300 zeros
			"0E-300":    "0",
			"-0E+369":   "0",
			"0.000":     "0",
			"1.50":      "1.50",
			"-1.50":     "-1.50",
			"123":       "123",
			"1E+5":      "100000",
			"0.0000125": "0.0000125",
		}
		for in, want := range cases {
			enc, err := encodeParameterValue(field, in, false)
			if err != nil {
				t.Fatalf("encode %s: %v", in, err)
			}
			got, err := decodeColumnValue(col, enc)
			if err != nil || got != want {
				t.Errorf("size %d: %s read back as %v (%v), want %s", size, in, got, err, want)
			}
		}
		// The largest exponent with a non-zero coefficient is a plain, long number, never
		// an unbounded string.
		enc, err := encodeParameterValue(field, "1E+369", false)
		if err == nil {
			got, _ := decodeColumnValue(col, enc)
			if s, _ := got.(string); len(s) > 400 {
				t.Errorf("1E+369 read back as %d characters", len(s))
			}
		}
	}
}

// NaN, SNaN and Infinity are not numbers: a read returns a typed error, never a string a
// caller could parse as one.
func TestDecfloatSpecialValuesAreATypedError(t *testing.T) {
	for _, size := range []int{8, 16} {
		field := decfloatField(size)
		col := columnMeta{Type: db2TypeDecfloat, Length: size, Precision: field.Precision}
		for _, v := range []string{"NaN", "-NaN", "SNaN", "Infinity", "-Infinity"} {
			enc, err := encodeParameterValue(field, v, false)
			if err != nil {
				t.Fatalf("encode %s: %v", v, err)
			}
			got, err := decodeColumnValue(col, enc)
			var special *DecfloatSpecialError
			if !errors.As(err, &special) || !errors.Is(err, ErrDecfloatNotFinite) || got != nil {
				t.Errorf("size %d: %s read as %v, %v; want *DecfloatSpecialError", size, v, got, err)
				continue
			}
			if !strings.Contains(strings.ToLower(v), strings.ToLower(special.Kind)) {
				t.Errorf("kind %q for %s", special.Kind, v)
			}
		}
	}
}
