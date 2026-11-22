package i400

import (
	"fmt"
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

// String is the redacted form.
func (c Config) String() string { return fmt.Sprintf("%+v", c) }

// GoString is the redacted form for %#v.
func (c Config) GoString() string { return fmt.Sprintf("%#v", c) }

func (c Config) redactedCopy() Config {
	out := c
	if out.Password != "" {
		out.Password = redacted
	}
	if out.DSN != "" {
		if u, err := url.Parse(out.DSN); err == nil {
			out.DSN = u.Redacted()
		} else {
			out.DSN = redacted
		}
	}
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
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	clone := cfg.clone()
	if clone.ConnectTimeout == 0 {
		clone.ConnectTimeout = defaultConnectTimeout
	}
	return &Connector{cfg: clone}, nil
}
