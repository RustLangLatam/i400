package i400

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

// Review findings 2 and 3: the password and query-string secrets stay out of JSON, slog's
// JSON handler, Config.DSN, and the reflection printing of a dereferenced connector or
// connection.

const querySecret = "Kq4-sslKeyMaterial-77"

func secretDSN() string {
	return "as400s://APPUSER:" + testSecret + "@ibmi.example/LIB?password=" + querySecret + "&sslKey=" + querySecret + "&passwordLevel=2&naming=sql"
}

func TestConfigNeverMarshalsOrLogsThePassword(t *testing.T) {
	cfg, err := ParseDSN(secretDSN())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := NewConnector(*cfg)
	if err != nil {
		t.Fatal(err)
	}
	outputs := map[string]string{}
	for name, v := range map[string]any{"Config": *cfg, "*Config": cfg, "*Connector": conn} {
		b, err := json.Marshal(v)
		if err == nil {
			outputs["json "+name] = string(b)
		}
		var sb strings.Builder
		slog.New(slog.NewJSONHandler(&sb, nil)).Info("x", "v", v)
		outputs["slog json "+name] = sb.String()
		var tb strings.Builder
		slog.New(slog.NewTextHandler(&tb, nil)).Info("x", "v", v)
		outputs["slog text "+name] = tb.String()
	}
	for where, out := range outputs {
		if strings.Contains(out, testSecret) || strings.Contains(out, querySecret) {
			t.Errorf("%s leaks a secret: %s", where, out)
		}
	}
	if got := cfg.LogValue().String(); strings.Contains(got, testSecret) {
		t.Errorf("LogValue leaks: %s", got)
	}
}

func TestStoredDSNAndFormattedQueryKeepNoSecrets(t *testing.T) {
	cfg, err := ParseDSN(secretDSN())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg.DSN, testSecret) || strings.Contains(cfg.DSN, querySecret) || strings.Contains(cfg.DSN, "?") {
		t.Errorf("Config.DSN keeps secrets or the query string: %s", cfg.DSN)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, *cfg); strings.Contains(out, querySecret) || strings.Contains(out, testSecret) {
			t.Errorf("%s of Config leaks: %s", verb, out)
		}
	}
	// A benign option that merely contains "pass" is not hidden from the driver.
	if cfg.RawQuery.Get("passwordLevel") != "2" {
		t.Error("passwordLevel must stay readable by the driver")
	}
}

func TestDereferencedConnectorAndConnPrintNoSecrets(t *testing.T) {
	d := &Driver{}
	dc, err := d.OpenConnector(secretDSN())
	if err != nil {
		t.Fatal(err)
	}
	connector := dc.(*Connector)
	cfg, _ := ParseDSN(secretDSN())
	conn := newConnFrom(*cfg, nil, nil, "", nil)
	for name, v := range map[string]any{"*c": *connector, "*conn": reflect.ValueOf(conn).Elem()} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			out := fmt.Sprintf(verb, v)
			if strings.Contains(out, testSecret) || strings.Contains(out, querySecret) {
				t.Errorf("%s with %s leaks through reflection: %.300s", name, verb, out)
			}
		}
	}
	// The secret still reaches the connection attempt.
	if connector.fullConfig().Password != testSecret || conn.fullConfig().Password != testSecret {
		t.Error("the password no longer reaches the connection")
	}
}
