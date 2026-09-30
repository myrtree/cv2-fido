package authenticator

import (
	"context"
	"errors"
	"log"
)

// Config supplies the platform operations used by the authenticator.
// Verify must require a fresh fingerprint; Session returns the owner's current
// eligible session identity or an error. Neither result is cached across requests.
// Notify must deliver the RP/action notification and return its cleanup function.
type Config struct {
	StateDir    string
	Signer      Signer
	Verify      func(context.Context) error
	Notify      func(context.Context, string, string) (func(), error)
	Session     func(context.Context) (string, error)
	Logger      *log.Logger
	DebugLogger *log.Logger
}

// Open exclusively locks and loads the credential store. Call Close after all
// requests have stopped. Logger defaults to log.Default; a nil DebugLogger
// disables request diagnostics.
func Open(config Config) (*Authenticator, error) {
	if config.Signer == nil || config.Verify == nil || config.Session == nil || config.Notify == nil {
		return nil, errors.New("signer, notification, fingerprint verification and session check are required")
	}

	state, err := openStore(config.StateDir)
	if err != nil {
		return nil, err
	}

	logger := config.Logger
	if logger == nil {
		logger = log.Default()
	}

	return &Authenticator{
		signer: config.Signer, store: state, verify: config.Verify,
		session: config.Session, notify: config.Notify, logger: logger, debug: config.DebugLogger,
	}, nil
}

// Close releases the credential store's exclusive process lock.
func (a *Authenticator) Close() error { return a.store.Close() }

// CredentialCount returns the number of stored registrations.
func (a *Authenticator) CredentialCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return len(a.store.credentials)
}
