package session

import (
	"github.com/godbus/dbus/v5"
	"testing"
)

func TestLocalUnlockedSession(t *testing.T) {
	valid := map[string]dbus.Variant{
		"Active": dbus.MakeVariant(true), "Remote": dbus.MakeVariant(false),
		"LockedHint": dbus.MakeVariant(false), "Type": dbus.MakeVariant("wayland"),
		"Class": dbus.MakeVariant("user"),
	}
	for _, tt := range []struct {
		name, property string
		value          any
		want           bool
	}{
		{"wayland", "Type", "wayland", true},
		{"x11", "Type", "x11", true},
		{"inactive", "Active", false, false},
		{"remote", "Remote", true, false},
		{"locked", "LockedHint", true, false},
		{"greeter", "Class", "greeter", false},
		{"tty", "Type", "tty", false},
		{"malformed", "Active", "true", false},
		{"missing lock hint", "LockedHint", nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			props := make(map[string]dbus.Variant)
			for k, v := range valid {
				props[k] = v
			}

			if tt.value == nil {
				delete(props, tt.property)
			} else {
				props[tt.property] = dbus.MakeVariant(tt.value)
			}

			if got := localUnlockedSession(props); got != tt.want {
				t.Fatalf("allowed=%v, want %v", got, tt.want)
			}
		})
	}
}
