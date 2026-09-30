package authenticator

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreUncertainCommitStopsFurtherOperations(t *testing.T) {
	s, err := openStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = s.Close() }() // Best-effort cleanup; preserve the operation result.

	c := credential{ID: make([]byte, 32), RP: "example.com", User: []byte{1}, Key: []byte{1}, Resident: true}
	if err := s.saveWithSync(c, func(*os.File) error { return errors.New("I/O error") }); err == nil {
		t.Fatal("sync error ignored")
	}

	if err := s.save(c); err == nil {
		t.Fatal("continued after uncertain commit")
	}

	a := &Authenticator{store: s}
	if status, _ := invoke(t, a, 2, map[int]any{1: "example.com", 2: make([]byte, 32)}); status != 0x7f {
		t.Fatalf("operation continued: %x", status)
	}
}

func TestStoreRestartAndLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	if other, err := openStore(dir); err == nil {
		_ = other.Close()
		t.Fatal("second process acquired store")
	}

	c := credential{ID: bytes.Repeat([]byte{1}, 32), RP: "example.com", User: []byte{1}, Key: []byte("TPM wrapped"), Resident: true}
	if err := s.save(c); err != nil {
		t.Fatal(err)
	}

	_ = s.Close()
	s, err = openStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = s.Close() }() // Best-effort cleanup; preserve the operation result.

	if len(s.credentials) != 1 || !bytes.Equal(s.credentials[0].ID, c.ID) {
		t.Fatal("credential lost after restart")
	}

	st, err := os.Stat(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}

	if st.Mode().Perm() != 0600 {
		t.Fatalf("permissions %o", st.Mode().Perm())
	}
}

func TestStoreFailureDoesNotCommit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = s.Close() }() // Best-effort cleanup; preserve the operation result.

	if err := os.Mkdir(filepath.Join(dir, "credentials.json"), 0700); err != nil {
		t.Fatal(err)
	}

	if err := s.save(credential{ID: make([]byte, 32), RP: "example.com", User: []byte{1}, Key: []byte{1}}); err == nil {
		t.Fatal("save succeeded over directory")
	}

	if len(s.credentials) != 0 {
		t.Fatal("failed save changed live state")
	}
}

func TestStoreRejectsCorruptionAndSymlinks(t *testing.T) {
	for _, content := range []string{"garbage", `{"version":99}`, `{"version":1,"credentials":[{}]}`} {
		t.Run(content, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "credentials.json"), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}

			if s, err := openStore(dir); err == nil {
				_ = s.Close()
				t.Fatal("accepted corrupt state")
			}
		})
	}

	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, "credentials.json")); err != nil {
		t.Fatal(err)
	}

	if s, err := openStore(dir); err == nil {
		_ = s.Close()
		t.Fatal("accepted symlink")
	}
}

func TestStoreRejectsInvalidAppend(t *testing.T) {
	for _, kind := range []string{"duplicate ID", "long RP", "duplicate resident"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			s, err := openStore(dir)
			if err != nil {
				t.Fatal(err)
			}

			defer func() { _ = s.Close() }()
			c := credential{ID: bytes.Repeat([]byte{1}, 32), RP: "example.com", User: []byte{1}, Key: []byte{1}, Resident: true}
			if err := s.save(c); err != nil {
				t.Fatal(err)
			}

			before, err := os.ReadFile(filepath.Join(dir, "credentials.json"))
			if err != nil {
				t.Fatal(err)
			}

			candidate := c
			candidate.ID = bytes.Repeat([]byte{2}, 32)
			switch kind {
			case "duplicate ID":
				candidate.ID = c.ID
				candidate.RP = "other.example"
			case "long RP":
				candidate.RP = string(bytes.Repeat([]byte{'a'}, maxRPIDSize+1))
			}

			if err := s.save(candidate); err == nil {
				t.Fatal("invalid append accepted")
			}

			after, err := os.ReadFile(filepath.Join(dir, "credentials.json"))
			if err != nil || !bytes.Equal(before, after) || len(s.credentials) != 1 || s.failed != nil {
				t.Fatal("rejected append changed store", err)
			}

			candidate.RP = "valid.example"
			candidate.ID = bytes.Repeat([]byte{3}, 32)
			if err := s.save(candidate); err != nil {
				t.Fatal("rejection prevented subsequent save", err)
			}
		})
	}
}

func TestStoreRejectsLongRPOnLoad(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}

	state := diskState{Version: 1, Credentials: []credential{{ID: make([]byte, 32), RP: string(bytes.Repeat([]byte{'a'}, maxRPIDSize+1)), User: []byte{1}, Key: []byte{1}}}}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	if s, err := openStore(dir); err == nil {
		_ = s.Close()
		t.Fatal("oversized RP accepted on load")
	}
}

func TestCredentialValidationReasons(t *testing.T) {
	valid := credential{ID: make([]byte, credentialIDSize), RP: "example.com", User: []byte{1}, Key: []byte{1}}
	for _, tc := range []struct {
		name   string
		change func(*credential)
		want   string
	}{
		{"id", func(c *credential) { c.ID = nil }, "credential ID length"},
		{"rp", func(c *credential) { c.RP = "" }, "RP ID length"},
		{"user", func(c *credential) { c.User = nil }, "user ID length"},
		{"key", func(c *credential) { c.Key = nil }, "wrapped key length"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			tc.change(&c)
			err := validateCredentials([]credential{c})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wrong diagnostic: %v", err)
			}
		})
	}
}
