package mta

import (
	"fmt"
	"sync"
	"time"
)

// TokenBucket is a token bucket. It is not safe for concurrent use; callers
// hold their own lock.
type TokenBucket struct {
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

// NewTokenBucket returns a full bucket that refills at rate tokens per second
// up to burst.
func NewTokenBucket(rate float64, burst int) *TokenBucket {
	if burst < 1 {
		burst = 1
	}
	return &TokenBucket{rate: rate, burst: float64(burst), tokens: float64(burst)}
}

// Take removes n tokens when they are there. When they are not it removes
// none and returns how long to wait until they would be.
func (b *TokenBucket) Take(now time.Time, n float64) (bool, time.Duration) {
	b.refill(now)
	if n > b.burst {
		// A request larger than the bucket could never be served whole: let it
		// through when the bucket is full and charge what is there.
		if b.tokens >= b.burst {
			b.tokens = 0
			return true, 0
		}
		n = b.burst
	}
	if b.tokens >= n {
		b.tokens -= n
		return true, 0
	}
	if b.rate <= 0 {
		return false, time.Hour
	}
	return false, time.Duration((n - b.tokens) / b.rate * float64(time.Second))
}

// SetRate changes the refill rate without touching the tokens.
func (b *TokenBucket) SetRate(rate float64, now time.Time) {
	b.refill(now)
	b.rate = rate
}

func (b *TokenBucket) refill(now time.Time) {
	if b.last.IsZero() {
		b.last = now
		return
	}
	if d := now.Sub(b.last); d > 0 {
		b.tokens += d.Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
}

// TenantLimit is a message rate for a tenant.
type TenantLimit struct {
	// Rate is recipients per second. Zero or negative means unlimited.
	Rate float64
	// Burst is the most recipients accepted at once; at least 1.
	Burst int
}

// TenantLimitError is returned by Submit when a tenant is over its rate.
type TenantLimitError struct {
	Tenant     string
	RetryAfter time.Duration
}

// Error implements error.
func (e *TenantLimitError) Error() string {
	return fmt.Sprintf("mta: tenant %q is over its rate; retry in %s", e.Tenant, e.RetryAfter.Round(time.Millisecond))
}

// TenantLimiter holds one token bucket per tenant.
type TenantLimiter struct {
	mu        sync.Mutex
	def       TenantLimit
	overrides map[string]TenantLimit
	buckets   map[string]*TokenBucket
}

// NewTenantLimiter returns a limiter that gives each tenant the default limit
// unless overrides names it.
func NewTenantLimiter(def TenantLimit, overrides map[string]TenantLimit) *TenantLimiter {
	return &TenantLimiter{def: def, overrides: overrides, buckets: make(map[string]*TokenBucket)}
}

// Allow charges n recipients to the tenant. It returns nil, or a
// *TenantLimitError.
func (l *TenantLimiter) Allow(tenant string, n int, now time.Time) error {
	if l == nil {
		return nil
	}
	lim, ok := l.overrides[tenant]
	if !ok {
		lim = l.def
	}
	if lim.Rate <= 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[tenant]
	if b == nil {
		if len(l.buckets) > 100_000 {
			// Idle tenants refill to full and cost nothing to forget.
			for k, v := range l.buckets {
				v.refill(now)
				if v.tokens >= v.burst {
					delete(l.buckets, k)
				}
			}
		}
		burst := lim.Burst
		if burst < 1 {
			burst = 1
		}
		b = NewTokenBucket(lim.Rate, burst)
		l.buckets[tenant] = b
	}
	if ok, wait := b.Take(now, float64(n)); !ok {
		return &TenantLimitError{Tenant: tenant, RetryAfter: wait}
	}
	return nil
}
