package fingerprint

import (
	"context"
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestFingerprintSignals(t *testing.T) {
	const sender = ":1.42"
	path := dbus.ObjectPath("/net/reactivated/Fprint/Device/0")
	sig := func(from string, body ...any) *dbus.Signal {
		return &dbus.Signal{Sender: from, Path: path, Name: fprintInterface + ".VerifyStatus", Body: body}
	}
	tests := []struct {
		name    string
		signals []*dbus.Signal
		success bool
	}{
		{"match", []*dbus.Signal{sig(sender, "verify-match", true)}, true},
		{"retry then match", []*dbus.Signal{sig(sender, "verify-retry-scan", false), sig(sender, "verify-match", true)}, true},
		{"no match", []*dbus.Signal{sig(sender, "verify-no-match", true)}, false},
		{"unknown", []*dbus.Signal{sig(sender, "future-status", true)}, false},
		{"nonterminal match", []*dbus.Signal{sig(sender, "verify-match", false)}, false},
		{"spoofed sender", []*dbus.Signal{sig(":1.99", "verify-match", true)}, false},
		{"bad body", []*dbus.Signal{sig(sender, "verify-match")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := make(chan *dbus.Signal, len(tt.signals))
			for _, s := range tt.signals {
				ch <- s
			}

			close(ch)
			err := waitFingerprint(context.Background(), ch, sender, path)
			if (err == nil) != tt.success {
				t.Fatalf("success=%v err=%v", tt.success, err)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitFingerprint(ctx, make(chan *dbus.Signal), sender, path); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
