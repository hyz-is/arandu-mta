package mta

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WarmupSchedule is the daily send quota of a new IP address. Mailbox
// providers learn to trust an address slowly, so a fresh one starts with a
// small quota that grows day by day.
type WarmupSchedule struct {
	// Days[i] is the quota, in recipients, on day i after the start; day 0 is
	// the day the address starts.
	Days []int
	// Unlimited lifts the quota after the last listed day. Without it the last
	// day's quota stays in force.
	Unlimited bool
}

// GeometricWarmup returns a schedule that starts at start recipients a day and
// multiplies by factor each day, for days days, then runs unlimited.
func GeometricWarmup(start int, factor float64, days int) WarmupSchedule {
	if start < 1 {
		start = 1
	}
	if factor < 1 {
		factor = 1
	}
	w := WarmupSchedule{Unlimited: true}
	q := float64(start)
	for i := 0; i < days; i++ {
		w.Days = append(w.Days, int(q))
		q *= factor
	}
	return w
}

// ParseWarmupSchedule reads a schedule written as comma separated daily
// quotas, "50,100,200,500", optionally ending in "unlimited" or "*" to lift the
// quota after the last day. White space is ignored. An empty string is the
// empty schedule, which means no quota.
func ParseWarmupSchedule(s string) (WarmupSchedule, error) {
	var w WarmupSchedule
	s = strings.TrimSpace(s)
	if s == "" {
		return w, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) > 3650 {
		return WarmupSchedule{}, errors.New("mta: warmup schedule is longer than ten years")
	}
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "unlimited" || p == "*" {
			if i != len(parts)-1 {
				return WarmupSchedule{}, errors.New("mta: warmup \"unlimited\" must be last")
			}
			w.Unlimited = true
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 1<<30 {
			return WarmupSchedule{}, fmt.Errorf("mta: warmup quota %q is not a positive number", p)
		}
		w.Days = append(w.Days, n)
	}
	if len(w.Days) == 0 && w.Unlimited {
		return WarmupSchedule{}, errors.New("mta: warmup schedule has no quota before \"unlimited\"")
	}
	return w, nil
}

// Quota returns the quota for the given day since the start, and false when
// there is none.
func (w WarmupSchedule) Quota(day int) (int, bool) {
	if len(w.Days) == 0 {
		return 0, false
	}
	if day < 0 {
		day = 0
	}
	if day >= len(w.Days) {
		if w.Unlimited {
			return 0, false
		}
		day = len(w.Days) - 1
	}
	return w.Days[day], true
}

// PoolIP is one source address of a pool.
type PoolIP struct {
	// Addr is the local address connections bind to.
	Addr netip.Addr
	// EHLOName is the name announced in EHLO from this address; it should be a
	// name whose reverse DNS is this address. Empty means Config.EHLOName.
	EHLOName string
	// Weight is the share of traffic among the pool's addresses with quota left;
	// 0 means 1.
	Weight int
	// Warmup is the daily quota schedule; the zero value means no quota.
	Warmup WarmupSchedule
	// WarmupStart is the day the schedule begins; the zero value means the day
	// the pool is created.
	WarmupStart time.Time
}

// IPPoolConfig describes one named pool.
type IPPoolConfig struct {
	Name string
	IPs  []PoolIP
	// Location is the time zone whose midnight starts a new warmup day: the
	// quota counters reset there and WarmupStart is read as a date there. The
	// zero value is UTC.
	Location *time.Location
}

// ErrQuotaExhausted means every address of the pool is at its daily quota.
// RetryAfter is the wait until the next day of the pool's Location (UTC by
// default), when the counters reset.
type ErrQuotaExhausted struct {
	Pool       string
	RetryAfter time.Duration
}

// Error implements error.
func (e *ErrQuotaExhausted) Error() string {
	return fmt.Sprintf("mta: every address of pool %q is at its daily quota", e.Pool)
}

// IPPools holds the pools the engine picks source addresses from.
type IPPools struct {
	mu    sync.Mutex
	pools map[string]*ipPool
}

type ipPool struct {
	name string
	loc  *time.Location
	ips  []*poolIP
}

type poolIP struct {
	PoolIP
	start   int64 // day number of the warmup start, in the pool's location
	loc     *time.Location
	usedDay int64 // day number the counter belongs to
	used    int
}

// dayIn numbers the calendar days of loc, so two instants have the same number
// exactly when loc's clock shows the same date.
func dayIn(t time.Time, loc *time.Location) int64 {
	y, m, d := t.In(loc).Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Unix() / 86400
}

// nextDay is the first instant of the day after t's, in loc.
func nextDay(t time.Time, loc *time.Location) time.Time {
	y, m, d := t.In(loc).Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, loc)
}

// NewIPPools builds the pools.
func NewIPPools(cfgs ...IPPoolConfig) (*IPPools, error) {
	p := &IPPools{pools: make(map[string]*ipPool, len(cfgs))}
	now := time.Now()
	for _, c := range cfgs {
		if c.Name == "" {
			return nil, errors.New("mta: ip pool needs a name")
		}
		if _, dup := p.pools[c.Name]; dup {
			return nil, fmt.Errorf("mta: ip pool %q is defined twice", c.Name)
		}
		if len(c.IPs) == 0 {
			return nil, fmt.Errorf("mta: ip pool %q has no addresses", c.Name)
		}
		loc := c.Location
		if loc == nil {
			loc = time.UTC
		}
		pool := &ipPool{name: c.Name, loc: loc}
		for _, ip := range c.IPs {
			if !ip.Addr.IsValid() {
				return nil, fmt.Errorf("mta: ip pool %q has an invalid address", c.Name)
			}
			if ip.Weight < 0 {
				return nil, fmt.Errorf("mta: ip pool %q has a negative weight", c.Name)
			}
			if ip.Weight == 0 {
				ip.Weight = 1
			}
			start := ip.WarmupStart
			if start.IsZero() {
				start = now
			}
			pool.ips = append(pool.ips, &poolIP{PoolIP: ip, start: dayIn(start, loc), loc: loc})
		}
		p.pools[c.Name] = pool
	}
	return p, nil
}

// Has reports whether a pool by that name exists.
func (p *IPPools) Has(name string) bool {
	if p == nil {
		return false
	}
	_, ok := p.pools[name]
	return ok
}

// IPLease is a reservation of quota on one source address.
type IPLease struct {
	// Addr is the address to bind.
	Addr netip.Addr
	// EHLOName is the name to announce from it; empty means the default.
	EHLOName string

	pools *IPPools
	ip    *poolIP
	day   int64
	n     int
}

// Release gives the quota back, for a transaction that never reached a server.
func (l *IPLease) Release() {
	if l == nil || l.ip == nil {
		return
	}
	l.pools.mu.Lock()
	if l.ip.usedDay == l.day {
		l.ip.used -= l.n
		if l.ip.used < 0 {
			l.ip.used = 0
		}
	}
	l.pools.mu.Unlock()
	l.ip = nil
}

func (ip *poolIP) remaining(now time.Time) (left int, limited bool) {
	today := dayIn(now, ip.loc)
	if ip.usedDay != today {
		ip.usedDay, ip.used = today, 0
	}
	day := int(today - ip.start)
	q, ok := ip.Warmup.Quota(day)
	if !ok {
		return 0, false
	}
	return q - ip.used, true
}

// Reserve picks an address of the pool for n recipients, weighted by Weight
// among those with quota left, and charges the quota. It returns a nil lease
// and a nil error when the pool does not exist, so the caller sends from the
// operating system's default address.
func (p *IPPools) Reserve(pool string, n int, now time.Time) (*IPLease, error) {
	if p == nil {
		return nil, nil
	}
	pl := p.pools[pool]
	if pl == nil {
		return nil, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	for _, ip := range pl.ips {
		if left, limited := ip.remaining(now); !limited || left > 0 {
			total += ip.Weight
		}
	}
	if total == 0 {
		return nil, &ErrQuotaExhausted{Pool: pool, RetryAfter: nextDay(now, pl.loc).Sub(now)}
	}
	pick := rand.IntN(total)
	for _, ip := range pl.ips {
		if left, limited := ip.remaining(now); limited && left <= 0 {
			continue
		}
		if pick < ip.Weight {
			ip.used += n
			return &IPLease{Addr: ip.Addr, EHLOName: ip.EHLOName, pools: p, ip: ip, day: ip.usedDay, n: n}, nil
		}
		pick -= ip.Weight
	}
	return nil, errors.New("mta: ip pool selection failed")
}

// IPUsage is how much of today's quota an address has used.
type IPUsage struct {
	Pool string
	Addr netip.Addr
	// Day is the warmup day, counted from 0, and Quota is that day's quota; a
	// Quota of 0 means unlimited.
	Day   int
	Quota int
	Used  int
}

// Usage reports every address's use today.
func (p *IPPools) Usage(now time.Time) []IPUsage {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []IPUsage
	for _, pl := range p.pools {
		for _, ip := range pl.ips {
			_, _ = ip.remaining(now)
			day := int(dayIn(now, ip.loc) - ip.start)
			q, _ := ip.Warmup.Quota(day)
			out = append(out, IPUsage{Pool: pl.name, Addr: ip.Addr, Day: day, Quota: q, Used: ip.used})
		}
	}
	return out
}

// RestoreUsage sets the use counter of an address for today, so a restart does
// not hand a warming address a fresh quota.
func (p *IPPools) RestoreUsage(pool string, addr netip.Addr, used int, now time.Time) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	pl := p.pools[pool]
	if pl == nil {
		return
	}
	for _, ip := range pl.ips {
		if ip.Addr == addr {
			ip.usedDay, ip.used = dayIn(now, ip.loc), used
		}
	}
}
