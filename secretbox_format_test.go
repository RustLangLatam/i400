package i400

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

// v0.1.1 finding 1: %s, %q and other non-%v verbs of a dereferenced *Connector or *Conn
// fell through fmt's bad-verb path, which prints the nested *secretBox with %v at depth 0
// and so showed the password.

// leaksSecret reports whether out contains the password as text, hex or a quoted form.
func leaksSecret(out string) bool {
	low := strings.ToLower(out)
	return strings.Contains(out, testSecret) ||
		strings.Contains(low, hex.EncodeToString([]byte(testSecret))) ||
		strings.Contains(out, fmt.Sprintf("%q", testSecret)) ||
		strings.Contains(out, fmt.Sprintf("%+q", testSecret))
}

// everyVerb is every ASCII letter as a verb, with and without each flag and a width.
func everyVerb() []string {
	var verbs []string
	for _, flags := range []string{"", "+", "#", "-", " ", "0", "+#", "10", "-30", ".3"} {
		for r := 'A'; r <= 'z'; r++ {
			if r > 'Z' && r < 'a' {
				continue
			}
			verbs = append(verbs, "%"+flags+string(r))
		}
	}
	return verbs
}

func secretCarriers(t *testing.T) map[string]any {
	t.Helper()
	cfg, err := ParseDSN(secretDSN())
	if err != nil {
		t.Fatal(err)
	}
	connector, err := NewConnector(*cfg)
	if err != nil {
		t.Fatal(err)
	}
	conn := newConnFrom(*cfg, nil, nil, "", nil)
	if connector.fullConfig().Password != testSecret || conn.fullConfig().Password != testSecret {
		t.Fatal("the password no longer reaches the connection")
	}
	box := connector.sec
	return map[string]any{
		"*Connector":            connector,
		"Connector":             *connector,
		"*Conn":                 conn,
		"Conn":                  reflect.ValueOf(conn).Elem().Interface(),
		"reflect.Value Conn":    reflect.ValueOf(conn).Elem(),
		"*secretBox":            box,
		"secretBox":             *box,
		"**secretBox":           &box,
		"[]Connector":           []Connector{*connector},
		"map[string]*secretBox": map[string]*secretBox{"k": box},
		"struct{Connector}":     struct{ C Connector }{*connector},
		"struct{unexported}":    struct{ c Connector }{*connector},
	}
}

func TestNoFmtVerbPrintsThePassword(t *testing.T) {
	for name, v := range secretCarriers(t) {
		for _, verb := range everyVerb() {
			if out := fmt.Sprintf(verb, v); leaksSecret(out) {
				t.Errorf("%s with %s leaks the password: %.200s", name, verb, out)
			}
		}
		for _, print := range []func(...any) string{fmt.Sprint, fmt.Sprintln} {
			if out := print(v); leaksSecret(out) {
				t.Errorf("%s with Sprint/Sprintln leaks the password", name)
			}
		}
	}
}

func TestSlogNeverPrintsThePassword(t *testing.T) {
	for name, v := range secretCarriers(t) {
		var text, js strings.Builder
		slog.New(slog.NewTextHandler(&text, nil)).Info("x", "v", v, slog.Any("any", v), slog.Group("g", "v", v))
		slog.New(slog.NewJSONHandler(&js, nil)).Info("x", "v", v, slog.Any("any", v), slog.Group("g", "v", v))
		if leaksSecret(text.String()) {
			t.Errorf("slog text handler leaks the password through %s: %s", name, text.String())
		}
		if leaksSecret(js.String()) {
			t.Errorf("slog JSON handler leaks the password through %s: %s", name, js.String())
		}
	}
}

func TestSecretBoxMethodsAreRedacted(t *testing.T) {
	box := newSecretBox(testSecret)
	js, err := box.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]string{
		"String":         box.String(),
		"GoString":       box.GoString(),
		"value String":   (*box).String(),
		"LogValue":       box.LogValue().String(),
		"MarshalJSON":    string(js),
		"Sprintf %s nil": fmt.Sprintf("%s", (*secretBox)(nil)),
	} {
		if leaksSecret(got) {
			t.Errorf("%s leaks: %s", name, got)
		}
		if !strings.Contains(got, redacted) && !strings.Contains(got, "nil") {
			t.Errorf("%s = %q, want the redaction marker", name, got)
		}
	}
}

// FuzzNoVerbPrintsThePassword formats a connector and a connection holding an arbitrary
// password with an arbitrary format string and checks that the password never appears.
func FuzzNoVerbPrintsThePassword(f *testing.F) {
	f.Add("s3cret-Pw-9137", "%s")
	f.Add("Kq4-77-zz", "%q %+q %#v %x")
	f.Add("abcdefgh", "%[1]*[2]s %v")
	f.Fuzz(func(t *testing.T, suffix, format string) {
		// The marker keeps the password from matching ordinary output by chance (a fuzzed
		// "00000000" appears in %b of any integer); a format that contains it is skipped.
		password := "Zq9#pw-marker:" + suffix
		if strings.Contains(format, password) {
			t.Skip()
		}
		cfg := Config{Host: "h.example", User: "U", Password: password}
		connector := newConnector(cfg)
		conn := newConnFrom(cfg, nil, nil, "", nil)
		for _, v := range []any{connector, *connector, conn, reflect.ValueOf(conn).Elem(), connector.sec, *connector.sec} {
			out := fmt.Sprintf(format, v, v, v)
			if strings.Contains(out, password) || strings.Contains(strings.ToLower(out), hex.EncodeToString([]byte(password))) {
				t.Fatalf("%q of %T printed the password: %q", format, v, out)
			}
		}
	})
}
