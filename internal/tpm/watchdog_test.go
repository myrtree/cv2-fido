package tpm

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestWatchdog(t *testing.T) {
	if mode := os.Getenv("CV2_TPM_WATCHDOG_TEST"); mode != "" {
		if mode == "blocked logger" {
			_, writer := io.Pipe()
			log.SetOutput(writer)
		}

		stop := watchdog(20 * time.Millisecond)
		if mode == "complete" {
			stop()
		}

		time.Sleep(250 * time.Millisecond)
		return
	}

	for _, mode := range []string{"blocked", "blocked logger", "complete"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWatchdog$")
			cmd.Env = append(os.Environ(), "CV2_TPM_WATCHDOG_TEST="+mode)
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatal("watchdog failed to terminate process")
			}

			if mode == "complete" {
				if err != nil {
					t.Fatalf("completed operation terminated: %v %s", err, out)
				}

				return
			}

			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 || (mode != "blocked logger" && !strings.Contains(string(out), "TPM operation timed out")) {
				t.Fatalf("unexpected watchdog result: %v %s", err, out)
			}
		})
	}
}
