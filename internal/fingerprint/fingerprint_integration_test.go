//go:build integration && linux

package fingerprint

import (
	"bufio"
	"context"
	"errors"
	"os/exec"
	"sync"
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

type testFingerprintService struct {
	Conn            *dbus.Conn
	NoMatch         bool
	mu              sync.Mutex
	claims, lists   []string
	stops, releases int
}

const testFingerprintPath = dbus.ObjectPath("/net/reactivated/Fprint/Device/0")

func (f *testFingerprintService) GetDefaultDevice() (dbus.ObjectPath, *dbus.Error) {
	return testFingerprintPath, nil
}
func (f *testFingerprintService) ListEnrolledFingers(username string) ([]string, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.lists = append(f.lists, username)
	return []string{"right-index-finger"}, nil
}
func (f *testFingerprintService) Claim(username string) *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.claims = append(f.claims, username)
	return nil
}
func (f *testFingerprintService) VerifyStart(finger string) *dbus.Error {
	if f.NoMatch {
		return nil
	}

	if err := f.Conn.Emit(testFingerprintPath, fprintInterface+".VerifyStatus", "verify-match", true); err != nil {
		return dbus.MakeFailedError(err)
	}

	return nil
}
func (f *testFingerprintService) VerifyStop() *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.stops++
	return nil
}
func (f *testFingerprintService) Release() *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.releases++
	return nil
}

func TestFingerprintOwnerIntegration(t *testing.T) {
	conn := testSystemBus(t)
	if _, err := conn.RequestName(fprintService, dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}

	f := &testFingerprintService{Conn: conn}
	if err := conn.Export(f, "/net/reactivated/Fprint/Manager", fprintService+".Manager"); err != nil {
		t.Fatal(err)
	}

	if err := conn.Export(f, testFingerprintPath, fprintInterface); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := CheckEnrollment(ctx, "alice"); err != nil {
		t.Fatal(err)
	}

	if err := Verify(ctx, "alice"); err != nil {
		t.Fatal(err)
	}

	if err := Verify(ctx, ""); err == nil {
		t.Fatal("accepted empty owner")
	}

	if err := CheckEnrollment(ctx, ""); err == nil {
		t.Fatal("accepted empty enrollment owner")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.lists) != 1 || f.lists[0] != "alice" || len(f.claims) != 1 || f.claims[0] != "alice" {
		t.Fatalf("wrong fprintd owner: lists=%v claims=%v", f.lists, f.claims)
	}

	if f.stops != 1 || f.releases != 1 {
		t.Fatalf("reader not released: stops=%d releases=%d", f.stops, f.releases)
	}
}

func TestVerificationDeadlineReleasesReader(t *testing.T) {
	conn := testSystemBus(t)
	if _, err := conn.RequestName(fprintService, dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}

	f := &testFingerprintService{Conn: conn, NoMatch: true}
	if err := conn.Export(f, "/net/reactivated/Fprint/Manager", fprintService+".Manager"); err != nil {
		t.Fatal(err)
	}

	if err := conn.Export(f, testFingerprintPath, fprintInterface); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := verify(ctx, "alice", 100*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected internal deadline, got %v", err)
	}

	if ctx.Err() != nil {
		t.Fatal("caller deadline expired")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stops != 1 || f.releases != 1 {
		t.Fatalf("reader not released: stops=%d releases=%d", f.stops, f.releases)
	}
}
