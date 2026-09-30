package tpm

import (
	"log"
	"os"
	"time"
)

const operationTimeout = 60 * time.Second

// A stuck device syscall cannot safely be cancelled by closing/reopening the
// fd. Terminate the process instead of admitting another operation; systemd
// restarts the service. This also bounds handle flushing and device close.
func watchdog(timeout time.Duration) func() {
	timer := time.AfterFunc(timeout, func() {
		logged := make(chan struct{})
		go func() {
			log.Print("TPM operation timed out; terminating service")
			close(logged)
		}()
		// A blocked logger must not defeat the watchdog.
		select {
		case <-logged:
		case <-time.After(100 * time.Millisecond):
		}

		os.Exit(1)
	})
	return func() { timer.Stop() }
}
