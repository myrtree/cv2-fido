package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("cv2-fido: ")
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, os.Args[1:], os.Stdout); exitStatus(err) != 0 {
		log.Print(err)
		os.Exit(exitStatus(err))
	}
}

// EX_CONFIG allows systemd to leave permanent configuration errors stopped.
const exitConfig = 78

var errConfiguration = errors.New("configuration")

func configurationError(message string) error {
	return fmt.Errorf("%w: %s", errConfiguration, message)
}

func exitStatus(err error) int {
	if err == nil || errors.Is(err, context.Canceled) {
		return 0
	}

	if errors.Is(err, errConfiguration) {
		return exitConfig
	}

	return 1
}
