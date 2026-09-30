//go:build integration && linux

package tpm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the real entry points and production deadline against a TPM socket
// that accepts commands but never responds. No host TPM is accessed.
func TestTPMStallWatchdog(t *testing.T) {
	if mode := os.Getenv("CV2_TPM_STALL_TEST"); mode != "" {
		path := os.Getenv("CV2_TPM_STALL_SOCKET")
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = listener.Close() }()
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			defer func() { _ = conn.Close() }()
			var header [10]byte
			if _, err := io.ReadFull(conn, header[:]); err == nil {
				fmt.Println("TPM command received")
				_, _ = io.Copy(io.Discard, conn)
			}
		}()
		backend := &TPM{devicePath: path}
		switch mode {
		case "open":
			_, err = New(path)
		case "register":
			_, _, _, err = backend.RegisterKey(make([]byte, 32))
		case "sign":
			key, encodeErr := encodeKey(wrappedKey{private: []byte{1}, public: []byte{1}, seed: make([]byte, 20)})
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}

			_, err = backend.SignASN1(key, make([]byte, 32), make([]byte, 32))
		}

		t.Fatal("blocked operation returned before watchdog", err)
	}

	for _, mode := range []string{"open", "register", "sign"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), operationTimeout+15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTPMStallWatchdog$")
			cmd.Env = append(os.Environ(), "CV2_TPM_STALL_TEST="+mode, "CV2_TPM_STALL_SOCKET="+filepath.Join(t.TempDir(), "tpm.sock"))
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 1 ||
				!strings.Contains(string(out), "TPM command received") || !strings.Contains(string(out), "TPM operation timed out") {
				t.Fatalf("TPM watchdog failed: %v %s", err, out)
			}
		})
	}
}
