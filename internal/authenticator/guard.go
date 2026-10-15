package authenticator

import (
	"context"
	"time"
)

const (
	requestBurst      = 20
	requestInterval   = 100 * time.Millisecond
	promptBurst       = 3
	promptInterval    = 10 * time.Second
	initialRetryDelay = 2 * time.Second
	maxRetryDelay     = 30 * time.Second
)

// Accessed only under Authenticator.mu. Limits are global, not keyed by an
// attacker-controlled RP ID or HID channel. Rejections never extend a cooldown.
type requestGuard struct {
	clock        func() time.Time
	requests     bucket
	prompts      bucket
	blockedUntil time.Time
	retryDelay   time.Duration
}

type bucket struct {
	updated     time.Time
	tokens      int
	initialized bool
}

func (b *bucket) take(now time.Time, capacity int, interval time.Duration) bool {
	if !b.initialized {
		b.updated, b.tokens, b.initialized = now, capacity, true
	}

	if elapsed := now.Sub(b.updated); elapsed >= interval {
		refill := min(int(elapsed/interval), capacity)
		b.tokens = min(b.tokens+refill, capacity)
		b.updated = now.Add(-(elapsed % interval))
	}

	if b.tokens == 0 {
		return false
	}

	b.tokens--
	return true
}

func (g *requestGuard) now() time.Time {
	if g.clock != nil {
		return g.clock()
	}

	return time.Now()
}

func (g *requestGuard) request() bool {
	return g.requests.take(g.now(), requestBurst, requestInterval)
}

func (g *requestGuard) prompt() bool {
	now := g.now()
	return !now.Before(g.blockedUntil) && g.prompts.take(now, promptBurst, promptInterval)
}

// waitPrompt holds the one active command until both prompt limits permit it.
// The HID loop continues keepalives and cancellation while this worker waits.
// Callers hold Authenticator.mu, so no other waiter can consume the budget.
func (g *requestGuard) waitPrompt(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		now := g.now()
		delay := max(time.Duration(0), g.blockedUntil.Sub(now))
		if g.prompts.initialized && g.prompts.tokens == 0 {
			delay = max(delay, g.prompts.updated.Add(promptInterval).Sub(now))
		}

		if delay <= 0 && g.prompt() {
			return nil
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (g *requestGuard) finish(success bool) {
	if success {
		g.retryDelay = 0
		g.blockedUntil = time.Time{}
		return
	}

	if g.retryDelay == 0 {
		g.retryDelay = initialRetryDelay
	} else {
		g.retryDelay = min(2*g.retryDelay, maxRetryDelay)
	}

	g.blockedUntil = g.now().Add(g.retryDelay)
}
