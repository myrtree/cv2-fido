//go:build integration && linux

package notification

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestBrokerIntegration(t *testing.T) {
	path := filepath.Join(socketTestDirectory(t), "notify.sock")
	b, err := Listen(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}

	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	shown := make(chan Request, 1)
	closed := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- ServeAgent(ctx, path, uint32(os.Getuid()), func(_ context.Context, r Request) (func(), error) {
			shown <- r
			return func() { closed <- struct{}{} }, nil
		})
	}()
	defer func() { cancel(); <-done }()

	for _, action := range []string{"authenticate", "register"} {
		requestCtx, end := context.WithCancel(ctx)
		cleanup, err := b.Show(requestCtx, "example.com", action)
		if err != nil {
			end()
			t.Fatal(err)
		}

		select {
		case r := <-shown:
			if r.RP != "example.com" || r.Action != action {
				t.Fatal("incorrect notification", r)
			}
		default:
			t.Fatal("notification acknowledged before delivery")
		}

		end() // Browser cancellation must close the notification too.
		select {
		case <-closed:
		case <-ctx.Done():
			t.Fatal("notification survived cancellation")
		}

		cleanup()
	}
}

func TestBrokerRejectsWrongOwner(t *testing.T) {
	path := filepath.Join(socketTestDirectory(t), "notify.sock")
	b, err := Listen(path, uint32(os.Getuid())+1)
	if err != nil {
		t.Fatal(err)
	}

	defer b.Close()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = conn.Close() }()

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	var denial Request
	if err := json.NewDecoder(conn).Decode(&denial); err != nil || denial.Action != actionOwnerDenied {
		t.Fatal("missing explicit owner rejection", err)
	}
}

func TestBrokerReplacesIdleHelper(t *testing.T) {
	path := filepath.Join(socketTestDirectory(t), "notify.sock")
	b, err := Listen(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}

	defer b.Close()

	oldClient, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}

	oldServer := <-b.waiting
	b.waiting <- oldServer
	_ = oldClient.Close()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- serveRequest(ctx, client, func(context.Context, Request) (func(), error) { return func() {}, nil })
	}()
	// The accept loop closes the old server connection when replacing it.
	for !errors.Is(oldServer.SetReadDeadline(time.Now()), net.ErrClosed) {
		select {
		case <-ctx.Done():
			t.Fatal("helper was not replaced")
		case <-time.After(time.Millisecond):
		}
	}

	cleanup, err := b.Show(ctx, "example.com", "authenticate")
	if err != nil {
		t.Fatal("first request after reconnect failed", err)
	}

	cleanup()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type delayedNotifications struct {
	entered chan string
	release chan struct{}
	closed  chan uint32
}

func (d *delayedNotifications) Notify(app string, replaces uint32, icon, title, body string, actions []string, hints map[string]dbus.Variant, expires int32) (uint32, *dbus.Error) {
	d.entered <- title
	<-d.release
	return 42, nil
}

func (d *delayedNotifications) CloseNotification(id uint32) *dbus.Error {
	d.closed <- id
	return nil
}

func TestLateDesktopNotificationIsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dbus-daemon", "--session", "--nofork", "--print-address=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	defer func() { cancel(); _ = cmd.Wait() }()

	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatal("private bus did not publish an address")
	}

	bus, err := dbus.Connect(scanner.Text())
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = bus.Close() }()

	d := &delayedNotifications{entered: make(chan string, 1), release: make(chan struct{}), closed: make(chan uint32, 1)}
	var once sync.Once
	release := func() { once.Do(func() { close(d.release) }) }
	defer release()

	if err := bus.Export(d, "/test", "org.freedesktop.Notifications"); err != nil {
		t.Fatal(err)
	}

	requestCtx, end := context.WithCancel(ctx)
	defer end()

	done := make(chan error, 1)
	go func() {
		cleanup, err := showDesktop(requestCtx, ctx, bus.Object(bus.Names()[0], "/test"), Request{RP: "example.com", Action: "authenticate"}, notificationTimeout)
		if cleanup != nil {
			cleanup()
		}

		done <- err
	}()
	select {
	case title := <-d.entered:
		if title != "Sign-in: example.com" {
			t.Fatal(title)
		}
	case <-ctx.Done():
		t.Fatal("Notify not received")
	}

	end() // Service already denied/cancelled the request; daemon replies later.
	release()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("late notification was acknowledged", err)
		}
	case <-ctx.Done():
		t.Fatal("late reply was not handled")
	}

	select {
	case id := <-d.closed:
		if id != 42 {
			t.Fatal("closed wrong notification", id)
		}
	default:
		t.Fatal("late notification left visible")
	}
}

func TestRejectedAgentStops(t *testing.T) {
	path := filepath.Join(socketTestDirectory(t), "notify.sock")
	b, err := Listen(path, uint32(os.Getuid())+1)
	if err != nil {
		t.Fatal(err)
	}

	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = ServeAgent(ctx, path, uint32(os.Getuid()), func(context.Context, Request) (func(), error) {
		t.Error("wrong owner received notification")
		return func() {}, nil
	})
	if !errors.Is(err, errOwnerDenied) || ctx.Err() != nil {
		t.Fatal("rejected agent kept retrying", err)
	}
}
