package authenticator

import "time"

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
