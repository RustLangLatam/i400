package i400

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

// redacted marks a value that was removed from formatted output.
const redacted = "[REDACTED]"

// configView has Config's fields and none of its methods, so formatting it does
// not call Config.Format again.
type configView Config

// Format makes every fmt verb (and slog's text and JSON handlers, which fall
// back to fmt) print the Config without its password, and without the value of
// any query option that looks like a secret.
func (c Config) Format(f fmt.State, verb rune) {
	view := configView(c.redactedCopy())
	_, _ = fmt.Fprintf(f, fmt.FormatString(f, verb), view)
}

// redactDSN drops the password and the whole query string of a DSN: query options can
// carry secrets (password, sslKey) and a stored DSN has no use for them.
func redactDSN(dsn string) string {
	if dsn == "" {
		return ""
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return redacted
	}
	u.RawQuery = ""
	return u.Redacted()
}

// LogValue keeps slog (its JSON handler included) from printing the password.
func (c Config) LogValue() slog.Value { return slog.StringValue(c.String()) }

// MarshalJSON encodes the redacted form: the password, the DSN's secrets and secret-looking
// query options never reach a JSON document.
func (c Config) MarshalJSON() ([]byte, error) { return json.Marshal(configView(c.redactedCopy())) }

// secretBox holds the password behind a pointer: fmt prints a nested pointer as an
// address, so reflection printing of a connector or connection cannot show it.
type secretBox struct{ password string }

// splitSecret returns cfg without its password, its secret-looking query options and its
// DSN's secrets, and the box that keeps the password for the connection attempt.
func splitSecret(cfg Config) (Config, *secretBox) {
	box := &secretBox{password: cfg.Password}
	cfg.Password = ""
	cfg.DSN = redactDSN(cfg.DSN)
	if cfg.RawQuery != nil {
		q := make(url.Values, len(cfg.RawQuery))
		for key, values := range cfg.RawQuery {
			if looksSecret(key) {
				q[key] = []string{redacted}
				continue
			}
			q[key] = append([]string(nil), values...)
		}
		cfg.RawQuery = q
	}
	return cfg, box
}

func (b *secretBox) apply(cfg Config) Config {
	if b != nil {
		cfg.Password = b.password
	}
	return cfg
}

// fullConfig is the configuration with the password, for the connection attempt only.
func (c *Connector) fullConfig() Config { return c.sec.apply(c.cfg) }

// fullConfig is the configuration with the password, for the cancel connection only.
func (c *Conn) fullConfig() Config { return c.sec.apply(c.cfg) }

// LogValue keeps slog from printing a connector's configuration.
func (c *Connector) LogValue() slog.Value { return slog.StringValue(fmt.Sprintf("%v", c)) }

// String is the redacted form.
func (c Config) String() string { return fmt.Sprintf("%+v", c) }

// GoString is the redacted form for %#v.
func (c Config) GoString() string { return fmt.Sprintf("%#v", c) }

func (c Config) redactedCopy() Config {
	out := c
	if out.Password != "" {
		out.Password = redacted
	}
	out.DSN = redactDSN(out.DSN)
	if c.RawQuery != nil {
		out.RawQuery = make(url.Values, len(c.RawQuery))
		for key, values := range c.RawQuery {
			if looksSecret(key) {
				out.RawQuery[key] = []string{redacted}
				continue
			}
			out.RawQuery[key] = append([]string(nil), values...)
		}
	}
	return out
}

func looksSecret(key string) bool {
	k := strings.ToLower(key)
	if k == "passwordlevel" { // an option about the password, not a secret
		return false
	}
	for _, word := range []string{"pass", "pwd", "secret", "token", "credential", "key"} {
		if strings.Contains(k, word) {
			return true
		}
	}
	return false
}

// Format prints the connector's redacted configuration.
func (c *Connector) Format(f fmt.State, verb rune) {
	if c == nil {
		_, _ = fmt.Fprint(f, "<nil>")
		return
	}
	_, _ = fmt.Fprintf(f, "i400.Connector{%s}", c.cfg.String())
}

// Format prints a connection without its configuration's secrets.
func (c *Conn) Format(f fmt.State, verb rune) {
	if c == nil {
		_, _ = fmt.Fprint(f, "<nil>")
		return
	}
	_, _ = fmt.Fprintf(f, "i400.Conn{host=%s user=%s job=%s}", c.cfg.Host, c.cfg.User, c.jobName)
}

// defaultConnectTimeout is what ParseDSN applies when the DSN sets none.
const defaultConnectTimeout = 15 * time.Second

// NewConnector validates cfg and returns a connector for sql.OpenDB. Use it
// instead of building a DSN string when the password, the CA pool or the server
// name come from configuration: nothing is parsed from or formatted into a URL.
func NewConnector(cfg Config) (*Connector, error) {
	clone := cfg.clone()
	if clone.ConnectTimeout == 0 {
		clone.ConnectTimeout = defaultConnectTimeout
	}
	switch {
	case clone.SocketTimeout == 0:
		clone.SocketTimeout = defaultSocketTimeout
	case clone.SocketTimeout < 0: // -1: explicitly no per-read bound
		clone.SocketTimeout = 0
	}
	if err := clone.Validate(); err != nil {
		return nil, err
	}
	return newConnector(clone), nil
}
