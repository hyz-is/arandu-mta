package mta

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
)

// MX is one mail exchanger of a domain.
type MX struct {
	Host string
	Pref uint16
}

// MXAnswer is the result of an MX lookup.
type MXAnswer struct {
	Records []MX
	// TTL is how long the answer may be cached. A resolver that cannot know it
	// returns 0 and the CachedResolver applies its default.
	TTL time.Duration
}

// AddrAnswer is the result of an address lookup.
type AddrAnswer struct {
	Addrs []netip.Addr
	TTL   time.Duration
}

// Resolver looks up the records the engine needs. An implementation reports a
// name that has no such records, whether the name does not exist or has no
// data of that type, as ErrNameNotFound, and every other failure as
// ErrDNSTemporary, so the engine can tell a verdict from a hiccup.
type Resolver interface {
	// LookupMX returns the MX records of domain, with their TTL.
	LookupMX(ctx context.Context, domain string) (MXAnswer, error)
	// LookupAddr returns the IPv4 and IPv6 addresses of host, with their TTL.
	LookupAddr(ctx context.Context, host string) (AddrAnswer, error)
}

var (
	// ErrNameNotFound means the name has no records of the type asked for.
	ErrNameNotFound = errors.New("mta: name not found")
	// ErrDNSTemporary means the lookup failed for a reason that may pass.
	ErrDNSTemporary = errors.New("mta: temporary DNS failure")
	// ErrNullMX means the domain publishes a null MX, RFC 7505: it accepts no
	// mail.
	ErrNullMX = errors.New("mta: domain accepts no mail (null MX)")
)

// NetResolver is a Resolver on the standard library's net.Resolver. The
// standard library reports no TTL, so its answers carry 0.
type NetResolver struct {
	// Resolver is the net.Resolver to use; nil means net.DefaultResolver.
	Resolver *net.Resolver
}

func (r NetResolver) resolver() *net.Resolver {
	if r.Resolver != nil {
		return r.Resolver
	}
	return net.DefaultResolver
}

func mapNetError(err error) error {
	var de *net.DNSError
	if errors.As(err, &de) && de.IsNotFound {
		return fmt.Errorf("%w: %v", ErrNameNotFound, err)
	}
	return fmt.Errorf("%w: %v", ErrDNSTemporary, err)
}

// LookupMX implements Resolver.
func (r NetResolver) LookupMX(ctx context.Context, domain string) (MXAnswer, error) {
	mx, err := r.resolver().LookupMX(ctx, domain)
	if err != nil {
		// The standard library returns the records it did find together with
		// an error when some of them are malformed.
		if len(mx) == 0 {
			return MXAnswer{}, mapNetError(err)
		}
	}
	ans := MXAnswer{Records: make([]MX, 0, len(mx))}
	for _, m := range mx {
		ans.Records = append(ans.Records, MX{Host: strings.TrimSuffix(strings.ToLower(m.Host), "."), Pref: m.Pref})
	}
	// A null MX is a single record whose host is the root; the trimmed host is
	// empty.
	return ans, nil
}

// LookupAddr implements Resolver.
func (r NetResolver) LookupAddr(ctx context.Context, host string) (AddrAnswer, error) {
	ips, err := r.resolver().LookupNetIP(ctx, "ip", host)
	if err != nil {
		return AddrAnswer{}, mapNetError(err)
	}
	if len(ips) == 0 {
		return AddrAnswer{}, fmt.Errorf("%w: %s", ErrNameNotFound, host)
	}
	for i := range ips {
		ips[i] = ips[i].Unmap()
	}
	return AddrAnswer{Addrs: ips}, nil
}

// CacheConfig sets the lifetimes of a CachedResolver.
type CacheConfig struct {
	// DefaultTTL applies to answers that carry no TTL. Zero means 5 minutes.
	DefaultTTL time.Duration
	// MinTTL and MaxTTL clamp the TTL of an answer. Zero MinTTL means 10
	// seconds, zero MaxTTL means 1 hour.
	MinTTL, MaxTTL time.Duration
	// NegativeTTL is how long "not found" is remembered. Zero means 1 minute.
	NegativeTTL time.Duration
	// MaxEntries bounds each cache. Zero means 100000.
	MaxEntries int
}

// CachedResolver caches a Resolver by TTL, remembers "not found", and sends one
// lookup for any number of concurrent callers of the same name.
type CachedResolver struct {
	inner   Resolver
	cfg     CacheConfig
	metrics *Metrics

	mu sync.Mutex
	mx map[string]*cacheEntry[MXAnswer]
	ad map[string]*cacheEntry[AddrAnswer]
}

type cacheEntry[T any] struct {
	val     T
	err     error
	expires time.Time
	pending chan struct{}
}

// NewCachedResolver wraps inner. metrics may be nil.
func NewCachedResolver(inner Resolver, cfg CacheConfig, metrics *Metrics) *CachedResolver {
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 5 * time.Minute
	}
	if cfg.MinTTL <= 0 {
		cfg.MinTTL = 10 * time.Second
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = time.Hour
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = time.Minute
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 100_000
	}
	if metrics == nil {
		metrics = new(Metrics)
	}
	return &CachedResolver{
		inner: inner, cfg: cfg, metrics: metrics,
		mx: make(map[string]*cacheEntry[MXAnswer]),
		ad: make(map[string]*cacheEntry[AddrAnswer]),
	}
}

func (c *CachedResolver) ttl(t time.Duration) time.Duration {
	if t <= 0 {
		return c.cfg.DefaultTTL
	}
	return min(max(t, c.cfg.MinTTL), c.cfg.MaxTTL)
}

func cachedLookup[T any](ctx context.Context, c *CachedResolver, cache map[string]*cacheEntry[T], key string,
	fetch func(context.Context, string) (T, time.Duration, error)) (T, error) {
	for {
		now := time.Now()
		c.mu.Lock()
		e := cache[key]
		switch {
		case e != nil && e.pending == nil && now.Before(e.expires):
			c.mu.Unlock()
			c.metrics.DNSCacheHits.Add(1)
			return e.val, e.err
		case e != nil && e.pending != nil:
			ch := e.pending
			c.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				var zero T
				return zero, ctx.Err()
			}
		}
		e = &cacheEntry[T]{pending: make(chan struct{})}
		cache[key] = e
		c.mu.Unlock()

		c.metrics.DNSLookups.Add(1)
		val, ttl, err := fetch(ctx, key)
		if err != nil {
			c.metrics.DNSErrors.Add(1)
		}

		c.mu.Lock()
		e.val, e.err = val, err
		switch {
		case err == nil:
			e.expires = time.Now().Add(c.ttl(ttl))
		case errors.Is(err, ErrNameNotFound):
			e.expires = time.Now().Add(c.cfg.NegativeTTL)
		default:
			e.expires = time.Time{} // never cache a hiccup
		}
		ch := e.pending
		e.pending = nil
		if len(cache) > c.cfg.MaxEntries {
			evict(cache, time.Now(), c.cfg.MaxEntries)
		}
		c.mu.Unlock()
		close(ch)
		return val, err
	}
}

func evict[T any](cache map[string]*cacheEntry[T], now time.Time, max int) {
	for k, e := range cache {
		if e.pending == nil && !now.Before(e.expires) {
			delete(cache, k)
		}
	}
	for k, e := range cache {
		if len(cache) <= max/2 {
			break
		}
		if e.pending == nil {
			delete(cache, k)
		}
	}
}

// LookupMX implements Resolver.
func (c *CachedResolver) LookupMX(ctx context.Context, domain string) (MXAnswer, error) {
	return cachedLookup(ctx, c, c.mx, domain, func(ctx context.Context, d string) (MXAnswer, time.Duration, error) {
		a, err := c.inner.LookupMX(ctx, d)
		return a, a.TTL, err
	})
}

// LookupAddr implements Resolver.
func (c *CachedResolver) LookupAddr(ctx context.Context, host string) (AddrAnswer, error) {
	return cachedLookup(ctx, c, c.ad, host, func(ctx context.Context, h string) (AddrAnswer, time.Duration, error) {
		a, err := c.inner.LookupAddr(ctx, h)
		return a, a.TTL, err
	})
}

// IPPreference orders the addresses of a mail exchanger.
type IPPreference uint8

const (
	// PreferIPv4 tries IPv4 addresses first, then IPv6.
	PreferIPv4 IPPreference = iota
	// PreferIPv6 tries IPv6 addresses first, then IPv4.
	PreferIPv6
	// IPv4Only never uses IPv6.
	IPv4Only
	// IPv6Only never uses IPv4.
	IPv6Only
	// AnyIP keeps the order the resolver returned.
	AnyIP
)

// orderAddrs filters and orders addrs by the preference. It reuses dst.
func orderAddrs(dst, addrs []netip.Addr, pref IPPreference, local netip.Addr) []netip.Addr {
	dst = dst[:0]
	want := func(a netip.Addr) bool {
		if !addrFamilyMatches(local, a) {
			return false
		}
		switch pref {
		case IPv4Only:
			return a.Is4()
		case IPv6Only:
			return a.Is6()
		}
		return true
	}
	first4 := pref != PreferIPv6
	switch pref {
	case AnyIP, IPv4Only, IPv6Only:
		for _, a := range addrs {
			if want(a) {
				dst = append(dst, a)
			}
		}
	default:
		for _, a := range addrs {
			if want(a) && a.Is4() == first4 {
				dst = append(dst, a)
			}
		}
		for _, a := range addrs {
			if want(a) && a.Is4() != first4 {
				dst = append(dst, a)
			}
		}
	}
	return dst
}

// sortMX orders records by preference and shuffles the ones that tie, as
// RFC 5321 section 5.1 asks, so load spreads over equal exchangers.
func sortMX(recs []MX) {
	if len(recs) > 64 {
		sort.SliceStable(recs, func(i, j int) bool { return recs[i].Pref < recs[j].Pref })
	} else {
		// A domain has a handful of exchangers; an insertion sort is stable and
		// allocates nothing.
		for i := 1; i < len(recs); i++ {
			for j := i; j > 0 && recs[j].Pref < recs[j-1].Pref; j-- {
				recs[j], recs[j-1] = recs[j-1], recs[j]
			}
		}
	}
	for i := 0; i < len(recs); {
		j := i + 1
		for j < len(recs) && recs[j].Pref == recs[i].Pref {
			j++
		}
		if j-i > 1 {
			g := recs[i:j]
			rand.Shuffle(len(g), func(a, b int) { g[a], g[b] = g[b], g[a] })
		}
		i = j
	}
}

// resolveMX returns the exchangers to try for a domain, in order: by
// preference, shuffled within a preference. A domain without MX records falls
// back to itself when it has an address, the implicit MX of RFC 5321 section
// 5.1. A null MX is ErrNullMX. A domain with neither is ErrNameNotFound. At most
// max hosts are returned, in buf's storage.
func resolveMX(ctx context.Context, r Resolver, domain string, max int, buf []MX) ([]MX, error) {
	ascii := domain
	if hasNonASCII(domain) {
		var err error
		if ascii, err = idna.Lookup.ToASCII(domain); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNameNotFound, err)
		}
	}
	ans, err := r.LookupMX(ctx, ascii)
	switch {
	case err == nil && len(ans.Records) == 0, errors.Is(err, ErrNameNotFound):
		if _, aerr := r.LookupAddr(ctx, ascii); aerr != nil {
			return nil, aerr
		}
		return append(buf[:0], MX{Host: ascii}), nil
	case err != nil:
		return nil, err
	}
	recs := append(buf[:0], ans.Records...)
	if len(recs) == 1 && (recs[0].Host == "" || recs[0].Host == ".") {
		return nil, ErrNullMX
	}
	out := recs[:0]
	for _, m := range recs {
		if m.Host != "" && m.Host != "." {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return nil, ErrNullMX
	}
	sortMX(out)
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out, nil
}
