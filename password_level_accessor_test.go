package i400

import (
	"database/sql"
	"testing"
)

// v0.1.1 finding 3: an application can read the password level the server announced in
// the signon reply, to audit it or alert on a weak host, without any password material.
func TestConnPasswordLevelReportsTheSignonLevel(t *testing.T) {
	for _, level := range []byte{2, 4} {
		// A subtest per level: its cleanup frees the fixed signon port for the next one.
		t.Run(string(rune('0'+level)), func(t *testing.T) {
			_, database := ucStartRig(t, ucDefaultSignon(level), ucDefaultDB())
			db := ucOpenDB(t, ucDSN(database.port(), ""))
			got, ok := rawPasswordLevel(t, db)
			if !ok || got != int(level) {
				t.Errorf("PasswordLevel() = %d, %v; want %d, true", got, ok, level)
			}
		})
	}
}

func TestConnPasswordLevelWithoutSignonInfo(t *testing.T) {
	if got, ok := (*Conn)(nil).PasswordLevel(); ok || got != 0 {
		t.Errorf("nil conn: %d, %v", got, ok)
	}
	if got, ok := newConnFrom(Config{}, nil, nil, "", nil).PasswordLevel(); ok || got != 0 {
		t.Errorf("conn without system info: %d, %v", got, ok)
	}
}

func rawPasswordLevel(t *testing.T, db *sql.DB) (level int, ok bool) {
	t.Helper()
	conn, err := db.Conn(ucContext(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Raw(func(dc any) error {
		level, ok = dc.(*Conn).PasswordLevel()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return level, ok
}
