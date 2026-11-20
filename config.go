package mta

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// DomainLimit limits traffic toward one destination domain.
type DomainLimit struct {
	// MaxConns is the most simultaneous connections. Zero means the engine's
	// MaxConnsPerDomain.
	MaxConns int
	// MessagesPerMinute is the most transactions started per minute. Zero means
	// no limit.
	MessagesPerMinute int
	// Burst is how many transactions may start at once before the rate applies.
	// Zero means a tenth of MessagesPerMinute, at least 1.
	Burst int
}

// AdaptiveConfig tunes how a destination domain is backed off when it asks the
// sender to slow down with a 421, a 451 or a 4.7.x reply.
type AdaptiveConfig struct {
	// BasePause is the pause after the first such reply; it doubles with each
	// further one. Zero means 30 seconds.
	BasePause time.Duration
	// MaxPause caps the pause. Zero means 15 minutes.
	MaxPause time.Duration
	// MaxLevel caps how many times the pause doubles and the connection limit
	// halves. Zero means 6.
	MaxLevel int
	// RecoverAfter is how many clean transactions lower the level by one. Zero
	// means 20.
	RecoverAfter int
}

// Config configures an Engine.
type Config struct {
	// Spool keeps the messages. Required.
	Spool Spool

	// Resolver finds mail exchangers; nil means NetResolver on the system
	// resolver. The engine caches it, see Cache.
	Resolver Resolver
	// Cache tunes the DNS cache.
	Cache CacheConfig

	// Signer, Classifier, Suppression, Events, MTASTS and Distributed are the
	// hooks the cluster wires in. All are optional; Classifier defaults to
	// DefaultClassifier.
	Signer      Signer
	Classifier  Classifier
	Suppression SuppressionChecker
	Events      EventSink
	MTASTS      MTASTSPolicySource
	Distributed DistributedLimiter

	// EHLOName is the name announced in EHLO when the source address has none;
	// it should be a name that resolves back to the sending address. Empty means
	// the host name.
	EHLOName string
	// Port is the TCP port of the exchangers. Zero means 25.
	Port int
	// Dial opens a connection; nil dials TCP and binds the source address.
	Dial func(ctx context.Context, t DialTarget) (net.Conn, error)

	// Workers is the number of delivery goroutines. Zero means 256.
	Workers int
	// MaxConnsPerDomain is the default of simultaneous connections toward one
	// destination domain. Zero means 10.
	MaxConnsPerDomain int
	// DefaultLimit applies to every domain; DomainLimits override it for a
	// domain by exact name or by a path.Match pattern such as "*.example.com".
	DefaultLimit DomainLimit
	DomainLimits map[string]DomainLimit
	// Adaptive tunes the back-off on throttling replies.
	Adaptive AdaptiveConfig
	// Tenant limits the recipients a tenant may submit per second.
	Tenant          TenantLimit
	TenantOverrides map[string]TenantLimit

	// Backoff is the retry schedule; Expiry is how long a message is retried.
	Backoff Backoff
	Expiry  time.Duration

	// Timeouts are the SMTP time limits.
	Timeouts Timeouts
	// DisableSTARTTLS stops the engine from encrypting, unless a policy forces
	// it. Off by default: STARTTLS is opportunistic.
	DisableSTARTTLS bool
	// RootCAs are the roots certificates are verified against; nil means the
	// system roots.
	RootCAs *x509.CertPool
	// UseChunking sends the message with BDAT when the server offers CHUNKING.
	UseChunking bool
	// IPPreference orders the addresses of an exchanger.
	IPPreference IPPreference
	// MaxMXHosts bounds the exchangers tried for one transaction. Zero means 5.
	MaxMXHosts int
	// IPs are the source address pools; nil sends from the default address.
	IPs *IPPools

	// MaxIdlePerHost and MaxIdleTotal bound the idle connection pool: per
	// exchanger address and in total. Zero means MaxConnsPerDomain and 1024.
	MaxIdlePerHost int
	MaxIdleTotal   int
	// IdleTimeout is how long an idle connection is kept. Zero means 30s.
	IdleTimeout time.Duration
	// MaxMessagesPerConn closes a connection after that many transactions. Zero
	// means 100.
	MaxMessagesPerConn int

	// MaxMessageSize bounds the data of one message. Zero means 50 MiB.
	MaxMessageSize int
	// MaxRecipients bounds the recipients of one message. Zero means 1000.
	MaxRecipients int

	// DisablePipelining stops the client from pipelining; it exists for tests.
	DisablePipelining bool

	// Metrics receives the counters; nil means the engine makes its own.
	Metrics *Metrics
}

func (c *Config) validate() error {
	if c.Spool == nil {
		return errors.New("mta: Config.Spool is required")
	}
	if c.Workers < 0 || c.MaxConnsPerDomain < 0 || c.Port < 0 || c.Port > 65535 {
		return errors.New("mta: negative or out-of-range Config value")
	}
	for k, v := range c.DomainLimits {
		if k == "" || v.MaxConns < 0 || v.MessagesPerMinute < 0 {
			return fmt.Errorf("mta: bad limit for domain %q", k)
		}
	}
	return nil
}

func (c *Config) defaults() {
	if c.Resolver == nil {
		c.Resolver = NetResolver{}
	}
	if c.Classifier == nil {
		c.Classifier = DefaultClassifier{}
	}
	if c.EHLOName == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			c.EHLOName = h
		} else {
			c.EHLOName = "localhost"
		}
	}
	if c.Port == 0 {
		c.Port = 25
	}
	if c.Dial == nil {
		c.Dial = defaultDial
	}
	if c.Workers == 0 {
		c.Workers = 256
	}
	if c.MaxConnsPerDomain == 0 {
		c.MaxConnsPerDomain = 10
	}
	if c.Adaptive.BasePause <= 0 {
		c.Adaptive.BasePause = 30 * time.Second
	}
	if c.Adaptive.MaxPause <= 0 {
		c.Adaptive.MaxPause = 15 * time.Minute
	}
	if c.Adaptive.MaxLevel <= 0 {
		c.Adaptive.MaxLevel = 6
	}
	if c.Adaptive.RecoverAfter <= 0 {
		c.Adaptive.RecoverAfter = 20
	}
	if c.Expiry <= 0 {
		c.Expiry = DefaultExpiry
	}
	c.Timeouts = c.Timeouts.withDefaults()
	if c.MaxMXHosts <= 0 {
		c.MaxMXHosts = 5
	}
	if c.MaxIdlePerHost <= 0 {
		// As many as the domain may hold open, so a burst does not close what the
		// next burst would reuse.
		c.MaxIdlePerHost = c.MaxConnsPerDomain
	}
	if c.MaxIdleTotal <= 0 {
		c.MaxIdleTotal = 1024
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 30 * time.Second
	}
	if c.MaxMessagesPerConn <= 0 {
		c.MaxMessagesPerConn = 100
	}
	if c.MaxMessageSize <= 0 {
		c.MaxMessageSize = 50 << 20
	}
	if c.MaxRecipients <= 0 {
		c.MaxRecipients = 1000
	}
	if c.Metrics == nil {
		c.Metrics = new(Metrics)
	}
}

// limitFor returns the limit that applies to a domain.
func (c *Config) limitFor(domain string) DomainLimit {
	l, ok := c.DomainLimits[domain]
	if !ok {
		best := ""
		for pat, v := range c.DomainLimits {
			if strings.ContainsAny(pat, "*?[") && matchPattern(pat, domain) && len(pat) > len(best) {
				l, ok, best = v, true, pat
			}
		}
	}
	if !ok {
		l = c.DefaultLimit
	}
	if l.MaxConns == 0 {
		l.MaxConns = c.MaxConnsPerDomain
		if c.DefaultLimit.MaxConns > 0 {
			l.MaxConns = c.DefaultLimit.MaxConns
		}
	}
	if l.MessagesPerMinute == 0 && !ok {
		l.MessagesPerMinute = c.DefaultLimit.MessagesPerMinute
	}
	return l
}
