package fingerprint

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

const verificationTimeout = 30 * time.Second

const fprintService = "net.reactivated.Fprint"
const fprintInterface = fprintService + ".Device"

func fingerprintDevice(ctx context.Context, conn *dbus.Conn) (dbus.ObjectPath, error) {
	var path dbus.ObjectPath
	err := conn.Object(fprintService, "/net/reactivated/Fprint/Manager").CallWithContext(ctx, fprintService+".Manager.GetDefaultDevice", 0).Store(&path)
	return path, err
}

// Verify requires a fresh match for the explicitly selected desktop owner.
func Verify(ctx context.Context, username string) error {
	return verify(ctx, username, verificationTimeout)
}

func verify(ctx context.Context, username string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if username == "" {
		return errors.New("fingerprint owner is required")
	}

	// A private connection scopes all signals to this operation and releases the
	// claim on disconnect, even if explicit cleanup fails.
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("connect to system bus: %w", err)
	}

	defer func() { _ = conn.Close() }() // Best-effort cleanup; preserve the operation result.

	path, err := fingerprintDevice(ctx, conn)
	if err != nil {
		return fmt.Errorf("get fingerprint device: %w", err)
	}

	var owner string
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, fprintService).Store(&owner); err != nil {
		return fmt.Errorf("resolve fprintd owner: %w", err)
	}

	dev := conn.Object(owner, path)
	if err := dev.CallWithContext(ctx, fprintInterface+".Claim", 0, username).Err; err != nil {
		return fmt.Errorf("claim fingerprint device: %w", err)
	}

	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		dev.CallWithContext(cleanup, fprintInterface+".VerifyStop", 0)
		dev.CallWithContext(cleanup, fprintInterface+".Release", 0)
	}()

	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	defer conn.RemoveSignal(signals)

	// Scope the bus match to fprintd's unique owner and check it again below.
	if err := conn.AddMatchSignalContext(ctx, dbus.WithMatchSender(owner), dbus.WithMatchObjectPath(path), dbus.WithMatchInterface(fprintInterface), dbus.WithMatchMember("VerifyStatus")); err != nil {
		return fmt.Errorf("subscribe to fingerprint status: %w", err)
	}

	if err := dev.CallWithContext(ctx, fprintInterface+".VerifyStart", 0, "any").Err; err != nil {
		return fmt.Errorf("start fingerprint verification: %w", err)
	}

	return waitFingerprint(ctx, signals, owner, path)
}

func waitFingerprint(ctx context.Context, signals <-chan *dbus.Signal, owner string, path dbus.ObjectPath) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case sig, ok := <-signals:
			if !ok {
				return errors.New("fingerprint connection closed")
			}

			if sig == nil || sig.Sender != owner || sig.Path != path || sig.Name != fprintInterface+".VerifyStatus" {
				continue
			}

			if len(sig.Body) != 2 {
				return errors.New("invalid fingerprint status")
			}

			status, ok := sig.Body[0].(string)
			if !ok {
				return errors.New("invalid fingerprint result")
			}

			done, ok := sig.Body[1].(bool)
			if !ok {
				return errors.New("invalid fingerprint completion flag")
			}

			if status == "verify-match" && done {
				// Reject the match if cancellation became observable after select.
				return ctx.Err()
			}

			switch status {
			case "verify-retry-scan", "verify-swipe-too-short", "verify-finger-not-centered", "verify-remove-and-retry", "verify-too-fast":
				if !done {
					continue
				}
			}

			return fmt.Errorf("fingerprint verification failed: %s", status)
		}
	}
}

// CheckEnrollment reports whether the selected owner has any enrolled fingers.
func CheckEnrollment(ctx context.Context, username string) error {
	if username == "" {
		return errors.New("fingerprint owner is required")
	}

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return err
	}

	defer func() { _ = conn.Close() }() // Best-effort cleanup; preserve the operation result.

	path, err := fingerprintDevice(ctx, conn)
	if err != nil {
		return err
	}

	var fingers []string
	if err := conn.Object(fprintService, path).CallWithContext(ctx, fprintInterface+".ListEnrolledFingers", 0, username).Store(&fingers); err != nil {
		return err
	}

	if len(fingers) == 0 {
		return errors.New("no enrolled fingers; run fprintd-enroll")
	}

	return nil
}
