//go:build integration && linux

package session

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// Each test owns a private bus. No request reaches host logind or fprintd.
func testSystemBus(t *testing.T) *dbus.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, "dbus-daemon", "--session", "--nofork", "--print-address=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal("integration requires dbus-daemon:", err)
	}

	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatal("private bus did not publish an address")
	}

	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", scanner.Text())
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

type testLoginSession struct {
	ID   string
	UID  uint32
	User string
	Seat string
	Path dbus.ObjectPath
}

type testLoginManager struct{ Sessions []testLoginSession }

func (m *testLoginManager) ListSessions() ([]testLoginSession, *dbus.Error) { return m.Sessions, nil }

type testSessionProperties struct{ Values map[string]dbus.Variant }

func (p *testSessionProperties) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	if iface != "org.freedesktop.login1.Session" {
		return nil, dbus.MakeFailedError(context.Canceled)
	}

	return p.Values, nil
}

func TestLogindIntegration(t *testing.T) {
	for _, tt := range []struct {
		name   string
		uid    uint32
		seat   string
		locked bool
		want   bool
	}{
		{"owner", 1000, "seat0", false, true},
		{"other user", 1001, "seat0", false, false},
		{"no local seat", 1000, "", false, false},
		{"locked", 1000, "seat0", true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn := testSystemBus(t)
			if _, err := conn.RequestName("org.freedesktop.login1", dbus.NameFlagDoNotQueue); err != nil {
				t.Fatal(err)
			}

			path := dbus.ObjectPath("/org/freedesktop/login1/session/test")
			manager := &testLoginManager{Sessions: []testLoginSession{{ID: "test", UID: tt.uid, User: "alice", Seat: tt.seat, Path: path}}}
			props := &testSessionProperties{Values: map[string]dbus.Variant{
				"Active": dbus.MakeVariant(true), "Remote": dbus.MakeVariant(false),
				"LockedHint": dbus.MakeVariant(tt.locked), "Class": dbus.MakeVariant("user"),
				"Type": dbus.MakeVariant("wayland"),
			}}
			if err := conn.Export(manager, "/org/freedesktop/login1", "org.freedesktop.login1.Manager"); err != nil {
				t.Fatal(err)
			}

			if err := conn.Export(props, path, "org.freedesktop.DBus.Properties"); err != nil {
				t.Fatal(err)
			}

			got, err := Active(context.Background(), conn, 1000)
			if (err == nil) != tt.want {
				t.Fatalf("session=%q err=%v", got, err)
			}

			if tt.want && got != string(path) {
				t.Fatal("wrong session identity", got)
			}

			if _, err := conn.ReleaseName("org.freedesktop.login1"); err != nil {
				t.Fatal(err)
			}

			if _, err := Active(context.Background(), conn, 1000); err == nil {
				t.Fatal("missing logind accepted")
			}
		})
	}
}

func TestStableSessionSelection(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint(reverse), func(t *testing.T) {
			conn := testSystemBus(t)
			if _, err := conn.RequestName("org.freedesktop.login1", dbus.NameFlagDoNotQueue); err != nil {
				t.Fatal(err)
			}

			first := testLoginSession{ID: "a", UID: 1000, Seat: "seat0", Path: "/org/freedesktop/login1/session/a"}
			second := first
			second.ID, second.Path = "b", "/org/freedesktop/login1/session/b"
			sessions := []testLoginSession{first, second}
			if reverse {
				sessions[0], sessions[1] = sessions[1], sessions[0]
			}

			if err := conn.Export(&testLoginManager{Sessions: sessions}, "/org/freedesktop/login1", "org.freedesktop.login1.Manager"); err != nil {
				t.Fatal(err)
			}

			props := &testSessionProperties{Values: map[string]dbus.Variant{
				"Active": dbus.MakeVariant(true), "Remote": dbus.MakeVariant(false), "LockedHint": dbus.MakeVariant(false), "Type": dbus.MakeVariant("wayland"), "Class": dbus.MakeVariant("user"),
			}}
			for _, s := range sessions {
				if err := conn.Export(props, s.Path, "org.freedesktop.DBus.Properties"); err != nil {
					t.Fatal(err)
				}
			}

			got, err := Active(context.Background(), conn, 1000)
			if err != nil || got != string(first.Path) {
				t.Fatalf("unstable selection: %q %v", got, err)
			}
		})
	}
}

type failedSessionProperties struct{ Name string }

func (p *failedSessionProperties) GetAll(string) (map[string]dbus.Variant, *dbus.Error) {
	return nil, dbus.NewError(p.Name, []interface{}{"session unavailable"})
}

func TestSessionLookupErrors(t *testing.T) {
	for _, name := range []string{"org.freedesktop.DBus.Error.UnknownObject", "org.freedesktop.login1.NoSuchSession", "org.freedesktop.DBus.Error.AccessDenied"} {
		t.Run(name, func(t *testing.T) {
			conn := testSystemBus(t)
			if _, err := conn.RequestName("org.freedesktop.login1", dbus.NameFlagDoNotQueue); err != nil {
				t.Fatal(err)
			}

			sessions := []testLoginSession{{ID: "a", UID: 1000, Seat: "seat0", Path: "/session/a"}, {ID: "b", UID: 1000, Seat: "seat0", Path: "/session/b"}}
			if err := conn.Export(&testLoginManager{Sessions: sessions}, "/org/freedesktop/login1", "org.freedesktop.login1.Manager"); err != nil {
				t.Fatal(err)
			}

			if err := conn.Export(&failedSessionProperties{Name: name}, sessions[0].Path, "org.freedesktop.DBus.Properties"); err != nil {
				t.Fatal(err)
			}

			props := &testSessionProperties{Values: map[string]dbus.Variant{
				"Active": dbus.MakeVariant(true), "Remote": dbus.MakeVariant(false), "LockedHint": dbus.MakeVariant(false), "Type": dbus.MakeVariant("wayland"), "Class": dbus.MakeVariant("user"),
			}}
			if err := conn.Export(props, sessions[1].Path, "org.freedesktop.DBus.Properties"); err != nil {
				t.Fatal(err)
			}

			got, err := Active(context.Background(), conn, 1000)
			if name != "org.freedesktop.DBus.Error.AccessDenied" {
				if err != nil || got != string(sessions[1].Path) {
					t.Fatal("vanished session prevented selection", err)
				}
			} else if err == nil {
				t.Fatal("unexpected session error ignored")
			}
		})
	}
}
