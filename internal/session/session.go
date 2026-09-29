package session

import (
	"context"
	"errors"
	"fmt"
	"github.com/godbus/dbus/v5"
	"time"
)

// Active trusts logind, never a username or session supplied by a browser.
// The returned identity is compared again before releasing an assertion.
func Active(ctx context.Context, conn *dbus.Conn, uid uint32) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var sessions []struct {
		ID   string
		UID  uint32
		User string
		Seat string
		Path dbus.ObjectPath
	}
	manager := conn.Object("org.freedesktop.login1", "/org/freedesktop/login1")
	if err := manager.CallWithContext(ctx, "org.freedesktop.login1.Manager.ListSessions", 0).Store(&sessions); err != nil {
		return "", fmt.Errorf("logind sessions: %w", err)
	}

	for _, session := range sessions {
		if session.UID != uid || session.Seat == "" {
			continue
		}

		var props map[string]dbus.Variant
		obj := conn.Object("org.freedesktop.login1", session.Path)
		err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0,
			"org.freedesktop.login1.Session").Store(&props)
		if err != nil {
			return "", fmt.Errorf("logind session: %w", err)
		}

		if localUnlockedSession(props) {
			return string(session.Path), nil
		}
	}

	return "", errors.New("owner needs an active, local, unlocked graphical session")
}

func localUnlockedSession(props map[string]dbus.Variant) bool {
	active, hasActive := props["Active"].Value().(bool)
	remote, hasRemote := props["Remote"].Value().(bool)
	locked, hasLocked := props["LockedHint"].Value().(bool)
	kind, _ := props["Type"].Value().(string)
	class, _ := props["Class"].Value().(string)
	known := hasActive && hasRemote && hasLocked
	graphical := kind == "wayland" || kind == "x11"
	return known && active && !remote && !locked && graphical && class == "user"
}
