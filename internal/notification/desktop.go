package notification

import (
	"context"
	"errors"
	"time"

	"github.com/godbus/dbus/v5"
)

const notificationTimeout = 30 * time.Second

// Desktop runs in the desktop user's session, never under the service account.
func Desktop(ctx context.Context, serviceUID uint32) error {
	bus, err := dbus.ConnectSessionBus()
	if err != nil {
		return err
	}

	defer func() { _ = bus.Close() }()

	lifetime := ctx
	return ServeAgent(ctx, SocketPath, serviceUID, func(ctx context.Context, request Request) (func(), error) {
		obj := bus.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
		return showDesktop(ctx, lifetime, obj, request, notificationTimeout)
	})
}

func showDesktop(ctx, lifetime context.Context, obj dbus.BusObject, request Request, timeout time.Duration) (func(), error) {
	body, err := request.Text()
	if err != nil {
		return nil, err
	}

	title := "Sign-in: " + request.RP
	if request.Action == "register" {
		title = "Register security key: " + request.RP
	}

	// Keep replies after request cancellation until the call timeout so their IDs
	// can be closed. Replies after that timeout are lost; notification removal
	// then depends on the daemon honoring the requested expiry.
	callCtx, cancel := context.WithTimeout(lifetime, timeout)
	defer cancel()
	var id uint32
	err = obj.CallWithContext(callCtx, "org.freedesktop.Notifications.Notify", 0,
		"cv2-fido", uint32(0), "dialog-password", title, body,
		[]string{}, map[string]dbus.Variant{"transient": dbus.MakeVariant(true)}, int32(notificationTimeout/time.Millisecond)).Store(&id)
	if err != nil {
		return nil, err
	}

	if id == 0 {
		return nil, errors.New("notification server returned an invalid ID")
	}

	closeNotification := func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		obj.CallWithContext(cleanup, "org.freedesktop.Notifications.CloseNotification", 0, id)
	}
	if err := ctx.Err(); err != nil {
		closeNotification()
		return nil, err
	}

	return closeNotification, nil
}
