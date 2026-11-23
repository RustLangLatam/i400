package i400

import (
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

func TestDecfloatAgainstJTOpen(t *testing.T) {
	data := `16 0 2238000000000000
16 1 2238000000000001
16 -1 a238000000000001
16 123.45 22300000000049c5
16 -0.001 a22c000000000001
16 9999999999999999 6e38ff3fcff3fcff
16 1234567890123456789 264534b9c1e28e57
16 1E+10 2260000000000001
16 1.5E-3 2228000000000015
16 0.1 2234000000000001
16 -98765.4321 a228000038fd51a1
16 12345678901234567890123456789012345678 269134b9c1e28e57
34 0 22080000000000000000000000000000
34 1 22080000000000000000000000000001
34 -1 a2080000000000000000000000000001
34 123.45 220780000000000000000000000049c5
34 -0.001 a2074000000000000000000000000001
34 9999999999999999 22080000000000000024ff3fcff3fcff
34 1234567890123456789 220800000000000014d2e7078a395bcf
34 1E+10 220a8000000000000000000000000001
34 1.5E-3 22070000000000000000000000000015
34 0.1 2207c000000000000000000000000001
34 -98765.4321 a2070000000000000000000038fd51a1
34 12345678901234567890123456789012345678 2609134b9c1e28e56f3c127177823535`
	// JTOpen rounds a value with more significant digits than the precision; this fork
	// refuses such a bind. These are the vectors that are skipped for that reason, and
	// each one must really need rounding, so a regression that starts refusing an exact
	// value cannot hide behind the skip.
	wantSkipped := map[string]bool{
		"16 1234567890123456789":                    true,
		"16 12345678901234567890123456789012345678": true,
		"34 12345678901234567890123456789012345678": true,
	}
	skipped := 0
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		f := strings.Fields(line)
		size, _ := strconv.Atoi(f[0])
		n := 8
		if size == 34 {
			n = 16
		}
		got, err := encodeDecfloat(f[1], n)
		if err != nil && strings.Contains(err.Error(), "cannot be stored exactly") {
			skipped++
			if !wantSkipped[f[0]+" "+f[1]] {
				t.Errorf("%d %s: refused, but it is not in the expected rounding set", size, f[1])
			}
			if digits, precision := significantDigits(f[1]), decfloatPrecision(size); digits <= precision {
				t.Errorf("%d %s: refused with %d significant digits, which fit the precision %d", size, f[1], digits, precision)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", line, err)
			continue
		}
		if hex.EncodeToString(got) != f[2] {
			t.Errorf("%d %s: got %x want %s", size, f[1], got, f[2])
		}
	}
	if skipped != len(wantSkipped) {
		t.Errorf("skipped %d vectors as needing rounding, want %d", skipped, len(wantSkipped))
	}
}

// decfloatPrecision is the coefficient digits of DECFLOAT(16) and DECFLOAT(34).
func decfloatPrecision(size int) int {
	if size == 34 {
		return 34
	}
	return 16
}

// significantDigits counts a decimal literal's coefficient digits without leading or
// trailing zeros, independently of the encoder under test.
func significantDigits(literal string) int {
	mantissa, _, _ := strings.Cut(strings.ToUpper(strings.TrimLeft(literal, "+-")), "E")
	digits := strings.Trim(strings.ReplaceAll(mantissa, ".", ""), "0")
	return len(digits)
}
