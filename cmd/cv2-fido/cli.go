package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"cv2-fido/internal/authenticator"
	"cv2-fido/internal/fingerprint"
	"cv2-fido/internal/hid"
	"cv2-fido/internal/notification"
	"cv2-fido/internal/session"
	"cv2-fido/internal/tpm"

	"github.com/godbus/dbus/v5"
)

const usage = `Usage: cv2-fido doctor | run [-user NAME] [-tpm /dev/tpmrm0] [-state DIR] [-debug]
       cv2-fido agent

doctor checks TPM/UHID access and enrolled fingerprints without creating keys.
Run both commands under the cv2-fido service account, not root or your desktop user.
The owner defaults to CV2_FIDO_USER, configured in /etc/cv2-fido.conf for systemd.
Credentials default to /var/lib/cv2-fido. See README.md for setup and migration.
agent runs under the desktop user and displays fingerprint request notifications.
`

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 1 && args[0] == "agent" {
		service, err := user.Lookup(serviceUser)
		if err != nil {
			return err
		}

		uid, err := strconv.ParseUint(service.Uid, 10, 32)
		if err != nil {
			return err
		}

		if os.Getuid() == 0 || uint32(os.Getuid()) == uint32(uid) {
			return errors.New("run agent as the desktop user")
		}

		return notification.Desktop(ctx, uint32(uid))
	}

	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		_, err := fmt.Fprint(out, usage)
		return err
	}

	if len(args) == 0 || (args[0] != "run" && args[0] != "doctor") {
		return errors.New(strings.TrimSpace(usage))
	}

	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(out)
	device := flags.String("tpm", "/dev/tpmrm0", "TPM resource manager device")
	dir := flags.String("state", "/var/lib/cv2-fido", "credential directory")
	owner := flags.String("user", os.Getenv("CV2_FIDO_USER"), "desktop owner of the enrolled fingerprints")
	debug := flags.Bool("debug", false, "log request metadata and FIDO status codes, without credential bytes")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return err
	}

	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}

	uid, err := configuredOwner(*owner)
	if err != nil {
		return err
	}

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return err
	}

	defer func() { _ = conn.Close() }() // Best-effort cleanup; preserve the operation result.

	checkSession := func(ctx context.Context) (string, error) { return session.Active(ctx, conn, uid) }
	if args[0] == "doctor" {
		return doctor(ctx, *device, *owner, checkSession, out)
	}

	if err := checkDeviceIsolation(*device); err != nil {
		return err
	}

	backend, err := tpm.New(*device)
	if err != nil {
		return fmt.Errorf("TPM: %w", err)
	}

	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = fingerprint.CheckEnrollment(checkCtx, *owner)
	cancel()
	if err != nil {
		return fmt.Errorf("fprintd: %w", err)
	}

	var logger *log.Logger
	if *debug {
		logger = log.Default()
	}

	broker, err := notification.Listen(notification.SocketPath, uid)
	if err != nil {
		return fmt.Errorf("notification broker: %w", err)
	}

	defer broker.Close()

	a, err := authenticator.Open(authenticator.Config{
		StateDir: *dir, Signer: backend, Session: checkSession, Logger: logger,
		Verify: func(ctx context.Context) error { return fingerprint.Verify(ctx, *owner) },
		Notify: broker.Show,
	})
	if err != nil {
		return err
	}

	defer func() { _ = a.Close() }() // Best-effort cleanup; preserve the operation result.

	log.Printf("starting virtual key; %d credentials; waiting for browser requests", a.CredentialCount())
	return hid.Run(ctx, a.HandleCommand, logger)
}

func doctor(ctx context.Context, device, owner string, session func(context.Context) (string, error), out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var problems []error
	var outputErr error
	check := func(name string, err error) {
		var writeErr error
		if err != nil {
			_, writeErr = fmt.Fprintf(out, "FAIL %s: %v\n", name, err)
			problems = append(problems, fmt.Errorf("%s: %w", name, err))
		} else {
			_, writeErr = fmt.Fprintf(out, "OK   %s\n", name)
		}

		if writeErr != nil {
			outputErr = writeErr
		}
	}
	_, err := tpm.New(device)
	check("device permissions and absence of legacy ACLs", checkDeviceIsolation(device))
	check("TPM device access (not a signing test)", err)
	f, err := os.OpenFile("/dev/uhid", os.O_RDWR, 0)
	if err == nil {
		err = f.Close()
	}

	check("UHID device access", err)
	check("fprintd enrollment for "+owner, fingerprint.CheckEnrollment(ctx, owner))
	_, err = session(ctx)
	check("owner's active local unlocked graphical session", err)
	if len(problems) > 0 {
		return errors.Join(errors.New("prerequisites missing; see README.md"), outputErr)
	}

	return outputErr
}
