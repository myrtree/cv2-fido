package authenticator

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOpenAuthenticatorOwnsStore(t *testing.T) {
	_, signer, _ := testAuthenticator(t)
	config := Config{
		Notify:   testNotify,
		StateDir: filepath.Join(t.TempDir(), "state"),
		Signer:   signer,
		Verify:   func(context.Context) error { return nil },
		Session:  func(context.Context) (string, error) { return "owner-session", nil },
	}
	a, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = a.Close() })
	if a.CredentialCount() != 0 {
		t.Fatal("new store is not empty")
	}

	if other, err := Open(config); err == nil {
		_ = other.Close()
		t.Fatal("second instance acquired the same store")
	}

	if status, _ := invoke(t, a, 1, registration()); status != 0 {
		t.Fatal(status)
	}

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = reopened.Close() }() // Best-effort cleanup; preserve the operation result.

	if reopened.CredentialCount() != 1 {
		t.Fatal("registration did not survive reopening")
	}
}

func TestOpenAuthenticatorRequiresAuthorization(t *testing.T) {
	_, signer, _ := testAuthenticator(t)
	for _, missing := range []string{"signer", "verify", "session", "notify"} {
		t.Run(missing, func(t *testing.T) {
			config := Config{
				Notify:   testNotify,
				StateDir: filepath.Join(t.TempDir(), "state"), Signer: signer,
				Verify:  func(context.Context) error { return nil },
				Session: func(context.Context) (string, error) { return "owner-session", nil },
			}
			switch missing {
			case "notify":
				config.Notify = nil
			case "signer":
				config.Signer = nil
			case "verify":
				config.Verify = nil
			case "session":
				config.Session = nil
			}

			if a, err := Open(config); err == nil {
				_ = a.Close()
				t.Fatal("accepted missing dependency", missing)
			}
		})
	}
}
