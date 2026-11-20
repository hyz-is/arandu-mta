package mta

import (
	"math/rand/v2"
	"time"
)

// DefaultBackoff is the retry schedule: the wait after the first failed
// attempt, after the second, and so on. After its last entry the wait stays
// at the last entry until the message expires.
var DefaultBackoff = []time.Duration{
	time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute,
	time.Hour, 2 * time.Hour, 4 * time.Hour,
}

// DefaultExpiry is how long the engine keeps retrying a message.
const DefaultExpiry = 72 * time.Hour

// Backoff is a retry schedule with jitter.
type Backoff struct {
	// Schedule is the wait after attempt 1, 2, 3...; the last entry repeats.
	// Empty means DefaultBackoff.
	Schedule []time.Duration
	// Jitter spreads each wait by up to this fraction either way, so a
	// thousand messages deferred together do not come back together. 0 means
	// 10%; a negative value disables it.
	Jitter float64
}

// Delay returns the wait after the given failed attempt, counted from 1.
func (b Backoff) Delay(attempt int) time.Duration {
	s := b.Schedule
	if len(s) == 0 {
		s = DefaultBackoff
	}
	if attempt < 1 {
		attempt = 1
	}
	i := attempt - 1
	if i >= len(s) {
		i = len(s) - 1
	}
	d := s[i]
	j := b.Jitter
	if j == 0 {
		j = 0.1
	}
	if j < 0 || d <= 0 {
		return d
	}
	if j > 1 {
		j = 1
	}
	// A uniform factor in [1-j, 1+j].
	f := 1 + j*(2*rand.Float64()-1)
	return time.Duration(float64(d) * f)
}
