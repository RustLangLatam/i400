package i400

import (
	"bytes"
	"os"
	"testing"
)

// Review finding 4: the client seed of the password exchange is random, not the clock.
func TestClientSeedIsRandom(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		s, err := newClientSeed()
		if err != nil || len(s) != 8 {
			t.Fatalf("seed %x: %v", s, err)
		}
		if seen[string(s)] {
			t.Fatalf("seed repeated after %d draws: %x", i, s)
		}
		seen[string(s)] = true
	}
	for _, f := range []string{"signon.go", "dbconn.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(src, []byte("UnixMilli")) {
			t.Errorf("%s still derives a value from the clock", f)
		}
	}
}
