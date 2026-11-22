package i400

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// Hardening contract: the password never appears in an error, a formatted
// Config, Connector or Conn, or a structured log record.

const testSecret = "s3cret-Pw-9137"

func TestConfigNeverFormatsThePassword(t *testing.T) {
	cfg := Config{Host: "ibmi.example", User: "APPUSER", Password: testSecret, DSN: "as400://APPUSER:" + testSecret + "@ibmi.example"}
	cfgPtr := &cfg
	conn, err := NewConnector(Config{Host: "ibmi.example", User: "APPUSER", Password: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]any{"Config": cfg, "*Config": cfgPtr, "*Connector": conn, "Conn": &Conn{cfg: cfg}}
	for name, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d"} {
			out := fmt.Sprintf(verb, v)
			if strings.Contains(out, testSecret) {
				t.Errorf("%s with %s leaks the password: %s", name, verb, out)
			}
		}
		if !strings.Contains(fmt.Sprintf("%+v", v), "APPUSER") && name != "Conn" {
			t.Errorf("%s: the user name should stay visible for diagnostics", name)
		}
	}
	var sb strings.Builder
	logger := slog.New(slog.NewTextHandler(&sb, nil))
	logger.Info("connecting", "config", cfg, "ptr", cfgPtr, "connector", conn)
	if strings.Contains(sb.String(), testSecret) {
		t.Errorf("slog record leaks the password: %s", sb.String())
	}
}

func TestParsedDSNKeepsNoPassword(t *testing.T) {
	cfg, err := ParseDSN("as400s://APPUSER:" + testSecret + "@ibmi.example/LIB")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != testSecret {
		t.Fatal("the password must still reach the connection")
	}
	if strings.Contains(cfg.DSN, testSecret) {
		t.Errorf("Config.DSN keeps the password: %s", cfg.DSN)
	}
	if strings.Contains(fmt.Sprintf("%+v", *cfg), testSecret) {
		t.Error("formatted parsed config leaks the password")
	}
}

func TestInvalidDSNErrorsNeverEchoTheDSN(t *testing.T) {
	dsns := []string{
		"as400://APPUSER:" + testSecret + "@ibmi.example:notaport/LIB",
		"as400://APPUSER:" + testSecret + "@ibmi.example/LIB?port=abc",
		"as400://APPUSER:" + testSecret + "@ibmi.example/LIB?tls=maybe",
		"as400://APPUSER:" + testSecret + "@ibmi.example/LIB?dateFormat=nope",
		"as400://APPUSER:" + testSecret + "@ibmi.example/LIB?insecureSkipVerify=true",
		"as400://APPUSER:" + testSecret + "@ibmi.example/LIB?tlsCAFile=/nonexistent",
		"as400://APPUSER:" + testSecret + "@ibmi.example/LIB?maxPacketBytes=-5",
		"as400://APPUSER:" + testSecret + "@ibmi.example/LIB?socketTimeout=never",
		"ftp://APPUSER:" + testSecret + "@ibmi.example/LIB",
		"as400://APPUSER:" + testSecret + "@:/LIB",
		"as400://APPUSER:" + testSecret + "@ibmi.example/%zz",
		"as400://APPUSER:" + testSecret + "@[::1/LIB",
		"://APPUSER:" + testSecret + "@ibmi.example",
	}
	for _, dsn := range dsns {
		_, err := ParseDSN(dsn)
		if err == nil {
			t.Errorf("DSN %q accepted", dsn)
			continue
		}
		if strings.Contains(err.Error(), testSecret) {
			t.Errorf("ParseDSN error leaks the password: %v", err)
		}
	}
}

func TestPasswordErrorsNeverEchoThePassword(t *testing.T) {
	seed := make([]byte, 8)
	for _, pw := range []string{"*" + testSecret, strings.Repeat("x", 300) + testSecret, ""} {
		for level := 0; level <= 4; level++ {
			_, err := passwordSubstitute("APPUSER", pw, level, seed, seed)
			if err != nil && strings.Contains(err.Error(), testSecret) {
				t.Errorf("level %d: error leaks the password: %v", level, err)
			}
		}
	}
}

func TestNewConnectorValidates(t *testing.T) {
	if _, err := NewConnector(Config{}); err == nil {
		t.Fatal("a config with no host was accepted")
	}
	if _, err := NewConnector(Config{Host: "h", MaxPacketBytes: -1}); err == nil {
		t.Fatal("an invalid config was accepted")
	}
}
