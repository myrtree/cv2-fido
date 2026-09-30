package authenticator

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGuardBurstAndRecovery(t *testing.T) {
	now := time.Unix(100, 0)
	g := requestGuard{clock: func() time.Time { return now }}
	for i := 0; i < requestBurst; i++ {
		if !g.request() {
			t.Fatal("initial request burst rejected")
		}
	}

	if g.request() {
		t.Fatal("unlimited request burst")
	}

	now = now.Add(requestInterval)
	if !g.request() || g.request() {
		t.Fatal("refill did not grant exactly one request")
	}

	for i := 0; i < promptBurst; i++ {
		if !g.prompt() {
			t.Fatal("initial prompt burst rejected")
		}

		g.finish(true)
	}

	if g.prompt() {
		t.Fatal("success reset the prompt budget")
	}

	now = now.Add(promptInterval)
	if !g.prompt() || g.prompt() {
		t.Fatal("prompt refill did not grant exactly one attempt")
	}
}

func TestGuardFailureBackoff(t *testing.T) {
	now := time.Unix(100, 0)
	g := requestGuard{clock: func() time.Time { return now }}
	for _, delay := range []int{2, 4, 8, 16, 30, 30} {
		g.finish(false)
		deadline := now.Add(time.Duration(delay) * time.Second)
		now = deadline.Add(-time.Nanosecond)
		if g.prompt() {
			t.Fatal("prompt allowed before backoff elapsed")
		}

		if !g.blockedUntil.Equal(deadline) {
			t.Fatal("rejection extended the cooldown")
		}

		now = deadline
	}

	g.finish(true)
	g.finish(false)
	if g.retryDelay != 2*time.Second {
		t.Fatal("successful verification did not reset the backoff")
	}
}

func TestNotificationAndPromptGuard(t *testing.T) {
	a, _, scans := testAuthenticator(t)
	now := time.Unix(100, 0)
	a.guard = requestGuard{clock: func() time.Time { return now }}
	notifications, closed := 0, 0
	a.notify = func(context.Context, string, string) (func(), error) {
		notifications++
		if *scans != 0 {
			t.Fatal("scanner activated before notification")
		}

		return nil, errors.New("notification unavailable")
	}
	if status, _ := invoke(t, a, 1, registration()); status != 0x27 || *scans != 0 {
		t.Fatal("notification failure allowed scanning")
	}

	a.notify = func(context.Context, string, string) (func(), error) {
		notifications++
		return func() { closed++ }, nil
	}
	if status, _ := invoke(t, a, 1, registration()); status != 0x27 || notifications != 1 {
		t.Fatal("cooldown produced another notification")
	}

	now = now.Add(2 * time.Second)
	if status, _ := invoke(t, a, 1, registration()); status != 0 || *scans != 1 || closed != 1 {
		t.Fatal("request did not recover after cooldown")
	}

	before := a.guard.prompts.tokens
	_, out := invoke(t, a, 2, map[int]any{
		1: "example.com", 2: make([]byte, 32),
		3: []descriptor{{Type: "public-key", ID: a.store.credentials[0].ID}},
		5: map[string]bool{"up": false},
	})
	if len(out) == 0 || notifications != 2 || *scans != 1 || a.guard.prompts.tokens != before {
		t.Fatal("preflight consumed a prompt or fingerprint")
	}
}

func TestNotificationMissingCleanupDeniesScan(t *testing.T) {
	a, _, scans := testAuthenticator(t)
	a.notify = func(context.Context, string, string) (func(), error) { return nil, nil }
	status, _ := invoke(t, a, 1, registration())
	if status != 0x27 || *scans != 0 {
		t.Fatalf("invalid notification callback allowed scanning: %x, scans=%d", status, *scans)
	}
}
