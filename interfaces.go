package mta

import (
	"context"
	"net/netip"
	"path"
	"strings"
	"time"
)

// Signer signs a message for a domain. The engine calls it once, in Submit,
// before the message is spooled, so the durable copy is the signed one and a
// retry never signs twice.
//
// Sign returns the whole message to send, signature header included. A message
// whose DKIMDomain is empty is not signed.
type Signer interface {
	Sign(ctx context.Context, domain string, message []byte) ([]byte, error)
}

// SignerFunc adapts a function to Signer.
type SignerFunc func(ctx context.Context, domain string, message []byte) ([]byte, error)

// Sign calls f.
func (f SignerFunc) Sign(ctx context.Context, domain string, message []byte) ([]byte, error) {
	return f(ctx, domain, message)
}

// Classifier turns an SMTP reply into a delivery outcome. DefaultClassifier is
// the minimal one; the cluster plugs a richer one in Config.Classifier.
type Classifier interface {
	Classify(code int, enhanced, text string) Classification
}

// ClassifierFunc adapts a function to Classifier.
type ClassifierFunc func(code int, enhanced, text string) Classification

// Classify calls f.
func (f ClassifierFunc) Classify(code int, enhanced, text string) Classification {
	return f(code, enhanced, text)
}

// SuppressionChecker tells the engine that a recipient must not be mailed. The
// engine asks before every attempt, so an address suppressed while a message
// waits in the queue is bounced instead of delivered.
type SuppressionChecker interface {
	// Suppressed reports whether address is suppressed for the tenant, and why.
	Suppressed(ctx context.Context, tenant, address string) (suppressed bool, reason string)
}

// SuppressionFunc adapts a function to SuppressionChecker.
type SuppressionFunc func(ctx context.Context, tenant, address string) (bool, string)

// Suppressed calls f.
func (f SuppressionFunc) Suppressed(ctx context.Context, tenant, address string) (bool, string) {
	return f(ctx, tenant, address)
}

// EventSink receives one Event per recipient outcome.
//
// The engine persists the new state of the recipient before it calls Emit, so a
// crash between the two loses an event and never repeats a delivery. The sink
// is where an application makes events durable: it should enqueue and return.
// An error is counted and logged by the metric EventErrors; the engine does not
// retry it. Emit is called from delivery goroutines and must be safe for
// concurrent use.
type EventSink interface {
	Emit(ctx context.Context, ev Event) error
}

// EventSinkFunc adapts a function to EventSink.
type EventSinkFunc func(ctx context.Context, ev Event) error

// Emit calls f.
func (f EventSinkFunc) Emit(ctx context.Context, ev Event) error { return f(ctx, ev) }

// MTASTSMode is the mode of an MTA-STS policy, RFC 8461.
type MTASTSMode uint8

const (
	// MTASTSNone means the domain publishes no enforceable policy.
	MTASTSNone MTASTSMode = iota
	// MTASTSTesting asks for TLS but must not stop delivery when it fails.
	MTASTSTesting
	// MTASTSEnforce forbids delivery to a host that does not match the policy,
	// does not offer STARTTLS, or presents a certificate that does not verify.
	MTASTSEnforce
)

// String returns "none", "testing" or "enforce".
func (m MTASTSMode) String() string {
	switch m {
	case MTASTSTesting:
		return "testing"
	case MTASTSEnforce:
		return "enforce"
	}
	return "none"
}

// MTASTSPolicy is a recipient domain's MTA-STS policy.
type MTASTSPolicy struct {
	Mode MTASTSMode
	// MX lists the host patterns the policy allows: an exact name, or "*." and a
	// suffix for any single leading label.
	MX []string
	// MaxAge is how long the policy may be cached; informational for the engine.
	MaxAge time.Duration
}

// MatchesMX reports whether host is allowed by the policy's mx patterns,
// RFC 8461 section 4.1. An empty list allows nothing, so a policy without mx
// lines never admits a host.
func (p MTASTSPolicy) MatchesMX(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}
	for _, pattern := range p.MX {
		pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
		if pattern == "" {
			continue
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			if len(host) > len(suffix) && strings.HasSuffix(host, suffix) && !strings.Contains(host[:len(host)-len(suffix)], ".") {
				return true
			}
			continue
		}
		if pattern == host {
			return true
		}
	}
	return false
}

// MTASTSPolicySource looks a policy up. The cluster implements it on top of
// arandu-mail's MTA-STS fetcher and its cache.
//
// A nil policy with a nil error means the domain has none. An error means the
// lookup failed: the engine then delivers as it would without a policy and
// counts the failure, because RFC 8461 section 5.1 lets a sender proceed when
// no valid policy, cached or fresh, can be had.
type MTASTSPolicySource interface {
	Policy(ctx context.Context, domain string) (*MTASTSPolicy, error)
}

// DistributedLimiter shares a limit between the nodes of a cluster. The engine
// asks before it starts a transaction toward a destination domain; the answer
// is a Redis script, a rate-limit service, or anything else the cluster runs.
type DistributedLimiter interface {
	// Allow asks for n sends toward key. When ok is false the engine waits
	// retryAfter before it asks again and does not count an attempt. An error
	// lets the send go ahead: a limiter that is down never stops the mail.
	Allow(ctx context.Context, key string, n int) (ok bool, retryAfter time.Duration, err error)
}

// DistributedLimiterFunc adapts a function to DistributedLimiter.
type DistributedLimiterFunc func(ctx context.Context, key string, n int) (bool, time.Duration, error)

// Allow calls f.
func (f DistributedLimiterFunc) Allow(ctx context.Context, key string, n int) (bool, time.Duration, error) {
	return f(ctx, key, n)
}

// matchPattern reports whether name matches a path.Match pattern; used by the
// per-domain limit overrides.
func matchPattern(pattern, name string) bool {
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}

// addrFamilyMatches reports whether a local and a remote address can be paired
// in one connection.
func addrFamilyMatches(local, remote netip.Addr) bool {
	if !local.IsValid() {
		return true
	}
	return local.Is4() == remote.Unmap().Is4()
}
