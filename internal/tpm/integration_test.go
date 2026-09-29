//go:build integration && linux

package tpm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
)

// Only sockets created by this helper reach the production backend. There is
// deliberately no TPM-device override, so this test cannot select /dev/tpm*.
func startEmulator(t *testing.T, state string) (*TPM, func()) {
	t.Helper()
	bin, err := exec.LookPath("swtpm")
	if err != nil {
		t.Fatal("integration tests require swtpm on PATH (Debian/Ubuntu: apt install swtpm)")
	}

	run := t.TempDir()
	socket := filepath.Join(run, "tpm.sock")
	logPath := filepath.Join(run, "swtpm.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	cmd := exec.CommandContext(ctx, bin, "socket", "--tpm2",
		"--tpmstate", "dir="+state,
		"--server", "type=unixio,path="+socket+",mode=0600",
		"--flags", "not-need-init,startup-clear")
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		cancel()
		_ = log.Close()
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }() // Termination by signal is expected during cleanup.
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = cmd.Process.Signal(syscall.SIGTERM) // The emulator may have already exited.
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				cancel()
				<-done
			}

			cancel()
			_ = log.Close()
		})
	}
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			data, _ := os.ReadFile(logPath)
			t.Logf("swtpm: %s", data)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			t.Fatal("swtpm exited before becoming ready")
		default:
		}

		if st, err := os.Stat(socket); err == nil && st.Mode()&os.ModeSocket != 0 {
			backend, err := New(socket)
			if err == nil {
				return backend, stop
			}
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("swtpm startup timed out")
	return nil, nil
}

func assertNoTransientKeys(t *testing.T, backend *TPM) {
	t.Helper()
	rw, err := backend.open()
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = rw.Close() }() // Best-effort cleanup; preserve the operation result.

	handles, more, err := tpm2.GetCapability(rw, tpm2.CapabilityHandles, 16, uint32(tpm2.HandleTypeTransient)<<24)
	if err != nil || more || len(handles) != 0 {
		t.Fatalf("transient keys leaked: handles=%v more=%t error=%v", handles, more, err)
	}
}

func TestTPMIntegration(t *testing.T) {
	parent := t
	state := t.TempDir()
	backend, stop := startEmulator(t, state)
	rp := sha256.Sum256([]byte("example.com"))
	digest := sha256.Sum256([]byte("integration assertion"))
	key, x, y, err := backend.RegisterKey(rp[:])
	if err != nil {
		t.Fatal(err)
	}

	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	assertNoTransientKeys(t, backend)
	checkSignature := func(t *testing.T) {
		t.Helper()
		sig, err := backend.SignASN1(key, rp[:], digest[:])
		if err != nil {
			t.Fatal(err)
		}

		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			t.Fatal("TPM signature did not verify")
		}

		other := sha256.Sum256([]byte("different assertion"))
		if ecdsa.VerifyASN1(pub, other[:], sig) {
			t.Fatal("signature accepted for wrong digest")
		}

		assertNoTransientKeys(t, backend)
	}
	t.Run("create and sign", checkSignature)
	t.Run("reload after emulator restart", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key.blob")
		if err := os.WriteFile(path, key, 0600); err != nil {
			t.Fatal(err)
		}

		rw, err := backend.open()
		if err != nil {
			t.Fatal(err)
		}

		err = tpm2.Shutdown(rw, tpm2.StartupClear)
		_ = rw.Close()
		if err != nil {
			t.Fatal(err)
		}

		stop()
		// Start on the parent test so cleanup runs after all signing subtests.
		backend, stop = startEmulator(parent, state)
		key, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		checkSignature(t)
	})
	for _, name := range []string{"wrong RP", "private blob", "public blob", "seed"} {
		t.Run(name, func(t *testing.T) {
			bad := bytes.Clone(key)
			badRP := rp
			k, err := decodeKey(bad)
			if err != nil {
				t.Fatal(err)
			}

			switch name {
			case "wrong RP":
				badRP = sha256.Sum256([]byte("other.example"))
			case "private blob":
				k.private[len(k.private)-1] ^= 1
			case "public blob":
				k.public[len(k.public)-1] ^= 1
			case "seed":
				k.seed[0] ^= 1
			}

			sig, err := backend.SignASN1(bad, badRP[:], digest[:])
			if err == nil || len(sig) != 0 || !strings.Contains(err.Error(), "load TPM signing key") {
				t.Fatalf("expected TPM Load rejection, got signature length=%d error=%v", len(sig), err)
			}

			checkSignature(t)
		})
	}

	t.Run("different TPM", func(t *testing.T) {
		other, _ := startEmulator(t, t.TempDir())
		sig, err := other.SignASN1(key, rp[:], digest[:])
		if err == nil || len(sig) != 0 || !strings.Contains(err.Error(), "load TPM signing key") {
			t.Fatalf("foreign TPM accepted key or failed before Load: %v", err)
		}

		assertNoTransientKeys(t, other)
		checkSignature(t)
	})
}
