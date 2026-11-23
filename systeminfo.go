package i400

type SystemInfo struct {
	System                string
	ServerVersion         int
	ServerLevel           int
	ServerCCSID           int
	ServerFunctionalLevel int
	ServerJobIdentifier   string
	PasswordLevel         int
	JobName               string
}

// PasswordLevel returns the password level (0 to 4) the server announced in its signon
// reply, which chose the password substitute this connection sent: 0 and 1 are DES, 2
// and 3 SHA-1, 4 PBKDF2-SHA-512. ok is false when the connection has no signon
// information. It carries no password material. Reach it through sql.Conn.Raw.
func (c *Conn) PasswordLevel() (level int, ok bool) {
	if c == nil || c.systemInfo == nil {
		return 0, false
	}
	return c.systemInfo.PasswordLevel, true
}
