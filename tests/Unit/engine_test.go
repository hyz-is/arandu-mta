package unit_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mta "github.com/hyz-is/arandu-mta"
	"github.com/hyz-is/arandu-mta/mtatest"
)

func TestThrottlingReplyBacksTheDomainOff(t *testing.T) {
	var first atomic.Bool
	h := newHarness(t, mtatest.Config{OnRcpt: func(string) *mtatest.Reply {
		if first.CompareAndSwap(false, true) {
			return rep(451, "4.7.1", "Our system has detected an unusual rate of mail; try again later")
		}
		return nil
	}}, func(c *mta.Config) {
		c.Adaptive = mta.AdaptiveConfig{BasePause: 300 * time.Millisecond, MaxPause: time.Second, RecoverAfter: 2}
	})
	h.submit(msg("th1", "a@example.com"))
	def := h.events.waitType(t, mta.EventDeferred, 1)[0]
	if !def.Class.Throttle {
		t.Fatalf("a 4.7.1 reply must be classified as throttling: %+v", def)
	}
	st := h.eng.Stats()
	if len(st.Domains) != 1 || st.Domains[0].Level != 1 || st.Domains[0].PausedUntil.IsZero() {
		t.Fatalf("domain stats after throttling: %+v", st.Domains)
	}
	h.submit(msg("th2", "a@example.com"))
	h.events.waitType(t, mta.EventDelivered, 2)
	for _, e := range h.events.ofType(mta.EventDelivered) {
		if wait := e.Time.Sub(def.Time); wait < 250*time.Millisecond {
			t.Fatalf("%s was delivered %s after the throttling reply; the domain must pause for 300ms", e.MessageID, wait)
		}
	}
	if h.eng.Metrics().Throttled.Load() != 1 {
		t.Fatalf("throttled = %d", h.eng.Metrics().Throttled.Load())
	}
	// Clean transactions bring the domain back to normal.
	for i := 0; i < 4; i++ {
		h.submit(msg("rec"+string(rune('a'+i)), "a@example.com"))
		h.events.waitType(t, mta.EventDelivered, 3+i)
	}
	if st := h.eng.Stats(); len(st.Domains) > 0 && st.Domains[0].Level != 0 {
		t.Fatalf("domain did not recover: %+v", st.Domains[0])
	}
}

func TestBanner421ThrottlesAndRecovers(t *testing.T) {
	h := newHarness(t, mtatest.Config{Greeting: func(n int) *mtatest.Reply {
		if n == 1 {
			return rep(421, "4.7.0", "too many connections from your address")
		}
		return nil
	}}, nil)
	h.submit(msg("b421", "a@example.com"))
	def := h.events.waitType(t, mta.EventDeferred, 1)[0]
	if def.Code != 421 || !def.Class.Throttle {
		t.Fatalf("event = %+v", def)
	}
	h.events.waitType(t, mta.EventDelivered, 1)
}

func TestConnectionsPerDomainAreCapped(t *testing.T) {
	var cur, peak atomic.Int32
	h := newHarness(t, mtatest.Config{OnData: func(*mtatest.Received) *mtatest.Reply {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		cur.Add(-1)
		return nil
	}}, func(c *mta.Config) { c.MaxConnsPerDomain = 3 })
	for i := 0; i < 30; i++ {
		h.submit(msg("cap"+itoa(i), "a@example.com"))
	}
	h.events.waitType(t, mta.EventDelivered, 30)
	if p := peak.Load(); p > 3 || p < 2 {
		t.Fatalf("peak concurrent transactions = %d, want 2 or 3 with a cap of 3", p)
	}
	if got := h.srv.Stats().Connections; got > 3 {
		t.Fatalf("connections opened = %d, cap is 3", got)
	}
}

func TestPerDomainLimitOverridesByPattern(t *testing.T) {
	var cur, peak atomic.Int32
	h := newHarness(t, mtatest.Config{OnData: func(*mtatest.Received) *mtatest.Reply {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		cur.Add(-1)
		return nil
	}}, func(c *mta.Config) {
		c.MaxConnsPerDomain = 8
		c.DomainLimits = map[string]mta.DomainLimit{"*.slow.test": {MaxConns: 1}}
	}, "mail.slow.test")
	for i := 0; i < 12; i++ {
		h.submit(msg("pat"+itoa(i), "a@mail.slow.test"))
	}
	h.events.waitType(t, mta.EventDelivered, 12)
	if p := peak.Load(); p != 1 {
		t.Fatalf("peak = %d, the pattern limit is 1", p)
	}
}

func TestMessagesPerMinuteLimit(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) {
		c.DomainLimits = map[string]mta.DomainLimit{"example.com": {MessagesPerMinute: 300, Burst: 1}} // 5 a second
	})
	start := time.Now()
	for i := 0; i < 6; i++ {
		h.submit(msg("rate"+itoa(i), "a@example.com"))
	}
	h.events.waitType(t, mta.EventDelivered, 6)
	if d := time.Since(start); d < 800*time.Millisecond {
		t.Fatalf("6 messages at 5 a second with a burst of 1 took %s, want at least 1s", d)
	}
}

func TestTransactionalBeatsMarketing(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	var order []string
	h := newHarness(t, mtatest.Config{OnData: func(m *mtatest.Received) *mtatest.Reply {
		subject := ""
		for _, l := range splitLines(string(m.Data)) {
			if len(l) > 9 && l[:9] == "Subject: " {
				subject = l[9:]
			}
		}
		if subject == "blocker" {
			once.Do(func() { close(started) })
			<-release
		}
		mu.Lock()
		order = append(order, subject)
		mu.Unlock()
		return nil
	}}, func(c *mta.Config) { c.MaxConnsPerDomain = 1 })
	h.submit(msg("blocker", "a@example.com"))
	<-started
	for i := 0; i < 4; i++ {
		m := msg("mk"+itoa(i), "a@example.com")
		m.Priority = mta.PriorityMarketing
		h.submit(m)
	}
	h.submit(msg("tx", "a@example.com"))
	close(release)
	h.events.waitType(t, mta.EventDelivered, 6)
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 6 || order[0] != "blocker" || order[1] != "tx" {
		t.Fatalf("delivery order = %v, want the transactional message right after the one in flight", order)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			l := s[start:i]
			if len(l) > 0 && l[len(l)-1] == '\r' {
				l = l[:len(l)-1]
			}
			out = append(out, l)
			start = i + 1
		}
	}
	return out
}

func TestTenantRateLimit(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) {
		c.Tenant = mta.TenantLimit{Rate: 1, Burst: 2}
		c.TenantOverrides = map[string]mta.TenantLimit{"vip": {Rate: 1000, Burst: 1000}}
	})
	h.submit(msg("tl1", "a@example.com"))
	h.submit(msg("tl2", "a@example.com"))
	var le *mta.TenantLimitError
	if err := h.eng.Submit(context.Background(), msg("tl3", "a@example.com")); !errors.As(err, &le) || le.Tenant != "org_1" || le.RetryAfter <= 0 {
		t.Fatalf("third Submit = %v, want a *TenantLimitError", err)
	}
	vip := msg("tl4", "a@example.com")
	vip.Tenant = "vip"
	h.submit(vip)
	if h.eng.Metrics().TenantLimited.Load() != 1 {
		t.Fatal("limit hit not counted")
	}
}

func TestDistributedLimiterDelaysWithoutCountingAnAttempt(t *testing.T) {
	var calls atomic.Int32
	lim := mta.DistributedLimiterFunc(func(_ context.Context, key string, n int) (bool, time.Duration, error) {
		if key != "domain:example.com" || n != 1 {
			t.Errorf("limiter asked for %q x%d", key, n)
		}
		if calls.Add(1) <= 2 {
			return false, 30 * time.Millisecond, nil
		}
		return true, 0, nil
	})
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) { c.Distributed = lim })
	h.submit(msg("dl1", "a@example.com"))
	ev := h.events.waitType(t, mta.EventDelivered, 1)[0]
	if ev.Attempt != 1 || len(h.events.ofType(mta.EventDeferred)) != 0 {
		t.Fatalf("a limiter delay must not count as an attempt: %+v", ev)
	}
	if h.eng.Metrics().LimiterDenied.Load() != 2 {
		t.Fatalf("denied = %d", h.eng.Metrics().LimiterDenied.Load())
	}

	// A limiter that fails lets the mail through.
	boom := mta.DistributedLimiterFunc(func(context.Context, string, int) (bool, time.Duration, error) {
		return false, time.Hour, errors.New("redis down")
	})
	h2 := newHarness(t, mtatest.Config{}, func(c *mta.Config) { c.Distributed = boom })
	h2.submit(msg("dl2", "a@example.com"))
	h2.events.waitType(t, mta.EventDelivered, 1)
	if h2.eng.Metrics().LimiterErrors.Load() != 1 {
		t.Fatal("limiter error not counted")
	}
}

func TestIPPoolQuotaEHLONameAndWarmup(t *testing.T) {
	warm, err := mta.ParseWarmupSchedule("2")
	if err != nil {
		t.Fatal(err)
	}
	pools, err := mta.NewIPPools(mta.IPPoolConfig{Name: "default", IPs: []mta.PoolIP{
		{Addr: netip.MustParseAddr("127.0.0.1"), EHLOName: "ip1.mta.test", Warmup: warm},
	}})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) { c.IPs = pools })
	for i := 0; i < 3; i++ {
		m := msg("ip"+itoa(i), "a@example.com")
		m.IPPool = "default"
		h.submit(m)
	}
	h.events.waitType(t, mta.EventDelivered, 2)
	time.Sleep(200 * time.Millisecond)
	if got := len(h.events.ofType(mta.EventDelivered)); got != 2 {
		t.Fatalf("delivered %d messages with a daily quota of 2", got)
	}
	for _, m := range h.srv.Messages() {
		if m.Helo != "ip1.mta.test" {
			t.Fatalf("EHLO name = %q, want the one of the source address", m.Helo)
		}
	}
	if h.eng.Metrics().QuotaExhausted.Load() == 0 {
		t.Fatal("quota exhaustion not counted")
	}
	if len(h.events.ofType(mta.EventDeferred)) != 0 {
		t.Fatal("waiting for quota must not produce delivery-delayed events")
	}
	u := pools.Usage(time.Now())
	if len(u) != 1 || u[0].Used != 2 || u[0].Quota != 2 || u[0].Day != 0 {
		t.Fatalf("usage = %+v", u)
	}
	if m, ok := h.eng.Message("ip2"); !ok || m.Recipients[0].State != mta.StateQueued {
		t.Fatalf("the third message should still be queued: %+v %v", m, ok)
	}
}

func TestIPPoolWeightedSelectionAndRelease(t *testing.T) {
	pools, err := mta.NewIPPools(mta.IPPoolConfig{Name: "p", IPs: []mta.PoolIP{
		{Addr: netip.MustParseAddr("192.0.2.1"), Weight: 1},
		{Addr: netip.MustParseAddr("192.0.2.2"), Weight: 9},
	}})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[netip.Addr]int{}
	now := time.Now()
	for i := 0; i < 20000; i++ {
		l, err := pools.Reserve("p", 1, now)
		if err != nil || l == nil {
			t.Fatal(l, err)
		}
		counts[l.Addr]++
	}
	share := float64(counts[netip.MustParseAddr("192.0.2.1")]) / 20000
	if share < 0.07 || share > 0.13 {
		t.Fatalf("share of the weight-1 address = %.3f, want about 0.10", share)
	}

	// An address at its quota is skipped, and a released lease frees quota.
	warm := mta.WarmupSchedule{Days: []int{1}}
	pools, _ = mta.NewIPPools(mta.IPPoolConfig{Name: "w", IPs: []mta.PoolIP{
		{Addr: netip.MustParseAddr("192.0.2.1"), Warmup: warm},
		{Addr: netip.MustParseAddr("192.0.2.2"), Warmup: warm},
	}})
	a, _ := pools.Reserve("w", 1, now)
	b, _ := pools.Reserve("w", 1, now)
	if a.Addr == b.Addr {
		t.Fatal("the second reservation went to an address already at its quota")
	}
	_, err = pools.Reserve("w", 1, now)
	var qe *mta.ErrQuotaExhausted
	if !errors.As(err, &qe) || qe.RetryAfter <= 0 || qe.RetryAfter > 24*time.Hour {
		t.Fatalf("third reservation = %v", err)
	}
	a.Release()
	if c, err := pools.Reserve("w", 1, now); err != nil || c.Addr != a.Addr {
		t.Fatalf("after Release: %v %v", c, err)
	}
	// An unknown pool is not an error: the default address is used.
	if l, err := pools.Reserve("nope", 1, now); l != nil || err != nil {
		t.Fatalf("unknown pool: %v %v", l, err)
	}
}

func TestWarmupGrowsDayByDay(t *testing.T) {
	w := mta.GeometricWarmup(50, 2, 4)
	want := []int{50, 100, 200, 400}
	for day, q := range want {
		if got, ok := w.Quota(day); !ok || got != q {
			t.Fatalf("day %d quota = %d %v, want %d", day, got, ok, q)
		}
	}
	if _, ok := w.Quota(4); ok {
		t.Fatal("after the schedule the quota must lift")
	}
	if got, ok := (mta.WarmupSchedule{Days: []int{10, 20}}).Quota(9); !ok || got != 20 {
		t.Fatalf("without Unlimited the last quota stays: %d %v", got, ok)
	}

	// A start date in the past moves the address along the schedule.
	start := time.Now().UTC().AddDate(0, 0, -2)
	pools, _ := mta.NewIPPools(mta.IPPoolConfig{Name: "p", IPs: []mta.PoolIP{
		{Addr: netip.MustParseAddr("192.0.2.1"), Warmup: w, WarmupStart: start},
	}})
	u := pools.Usage(time.Now())
	if u[0].Day != 2 || u[0].Quota != 200 {
		t.Fatalf("usage = %+v, want day 2 with quota 200", u[0])
	}
	pools.RestoreUsage("p", netip.MustParseAddr("192.0.2.1"), 150, time.Now())
	if u := pools.Usage(time.Now()); u[0].Used != 150 {
		t.Fatalf("restored usage = %+v", u[0])
	}
}

func TestCancel(t *testing.T) {
	h := newHarness(t, mtatest.Config{OnRcpt: func(to string) *mtatest.Reply {
		if to == "late@example.com" {
			return rep(451, "4.2.0", "try later")
		}
		return nil
	}}, func(c *mta.Config) {
		c.Backoff = mta.Backoff{Schedule: []time.Duration{5 * time.Second}, Jitter: -1}
		c.Expiry = time.Hour
	})
	h.submit(msg("cx1", "now@example.com", "late@example.com"))
	h.events.waitType(t, mta.EventDeferred, 1)
	res, err := h.eng.Cancel(context.Background(), "cx1")
	if err != nil || res.Cancelled != 1 || res.Settled != 1 || res.InFlight != 0 {
		t.Fatalf("Cancel = %+v, %v", res, err)
	}
	if _, err := h.eng.Cancel(context.Background(), "cx1"); !errors.Is(err, mta.ErrNotFound) {
		t.Fatalf("second Cancel = %v, want ErrNotFound (the message is complete and gone)", err)
	}
	if _, err := h.eng.Cancel(context.Background(), "nope"); !errors.Is(err, mta.ErrNotFound) {
		t.Fatalf("Cancel of an unknown id = %v", err)
	}
	if err := h.eng.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.spool.(*mta.MemorySpool).Len() != 0 {
		t.Fatal("cancelled message left in the spool")
	}
	if h.eng.Metrics().Cancelled.Load() != 1 {
		t.Fatal("cancel not counted")
	}
}

func TestCancelBeforeAnAttempt(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) {
		c.Distributed = mta.DistributedLimiterFunc(func(context.Context, string, int) (bool, time.Duration, error) {
			return false, time.Hour, nil // hold every message
		})
	})
	h.submit(msg("cx2", "a@example.com"))
	time.Sleep(50 * time.Millisecond)
	res, err := h.eng.Cancel(context.Background(), "cx2")
	if err != nil || res.Cancelled != 1 {
		t.Fatalf("Cancel = %+v, %v", res, err)
	}
	if h.srv.Stats().Connections != 0 {
		t.Fatal("a cancelled message reached the network")
	}
}

func TestStatsAndMessageSnapshot(t *testing.T) {
	h := newHarness(t, mtatest.Config{OnData: func(*mtatest.Received) *mtatest.Reply {
		return rep(451, "4.0.0", "later")
	}}, func(c *mta.Config) {
		c.Backoff = mta.Backoff{Schedule: []time.Duration{10 * time.Second}, Jitter: -1}
		c.Expiry = time.Hour
	}, "example.com", "example.org")
	h.submit(msg("st1", "a@example.com", "b@example.org"))
	other := msg("st2", "c@example.com")
	other.Tenant = "org_2"
	h.submit(other)
	h.events.waitType(t, mta.EventDeferred, 3)
	st := h.eng.Stats()
	if st.Messages != 2 || st.PendingRecipients != 3 || len(st.Domains) != 2 || len(st.Tenants) != 2 {
		t.Fatalf("stats = %+v", st)
	}
	if st.Domains[0].Domain != "example.com" || st.Domains[0].Delayed != 2 || st.Domains[1].Delayed != 1 {
		t.Fatalf("domain stats = %+v", st.Domains)
	}
	if st.Tenants[0].Tenant != "org_1" || st.Tenants[0].Pending != 2 || st.Tenants[1].Pending != 1 {
		t.Fatalf("tenant stats = %+v", st.Tenants)
	}
	m, ok := h.eng.Message("st1")
	if !ok || len(m.Recipients) != 2 || m.Recipients[0].State != mta.StateDeferred || m.Recipients[0].LastCode != 451 || m.Recipients[0].Attempts != 1 || m.NextAttempt.IsZero() {
		t.Fatalf("snapshot = %+v", m)
	}
	m.Recipients[0].State = mta.StateBounced // a snapshot is a copy
	if again, _ := h.eng.Message("st1"); again.Recipients[0].State != mta.StateDeferred {
		t.Fatal("Message returned the engine's own state")
	}
}

func TestShutdownKeepsQueuedMessagesInTheSpool(t *testing.T) {
	dir := tempDir(t)
	spool, err := mta.OpenDiskSpool(dir, mta.DiskSpoolOptions{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, mtatest.Config{OnData: func(*mtatest.Received) *mtatest.Reply {
		return rep(451, "4.0.0", "later")
	}}, func(c *mta.Config) {
		c.Spool = spool
		c.Backoff = mta.Backoff{Schedule: []time.Duration{10 * time.Second}, Jitter: -1}
		c.Expiry = time.Hour
	})
	h.submit(msg("sd1", "a@example.com"))
	h.events.waitType(t, mta.EventDeferred, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.eng.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	var found []*mta.Message
	if err := spool.Load(ctx, func(m *mta.Message) error { found = append(found, m); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ID != "sd1" || found[0].Recipients[0].State != mta.StateDeferred || found[0].Recipients[0].Attempts != 1 {
		t.Fatalf("spool after Shutdown: %+v", found)
	}
}

func TestShutdownWaitsForTheTransactionInFlight(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	h := newHarness(t, mtatest.Config{OnData: func(*mtatest.Received) *mtatest.Reply {
		close(started)
		<-release
		return nil
	}}, nil)
	h.submit(msg("if1", "a@example.com"))
	<-started
	done := make(chan error, 1)
	go func() { done <- h.eng.Shutdown(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("Shutdown returned %v while a transaction was running", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ev := h.events.all()
	if len(ev) != 1 || ev[0].Type != mta.EventDelivered {
		t.Fatalf("the in-flight message must settle before Shutdown returns: %s", describe(ev))
	}
}

func TestShutdownTimeoutCutsTheTransactionOff(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	h := newHarness(t, mtatest.Config{OnData: func(*mtatest.Received) *mtatest.Reply {
		close(started)
		<-release
		return nil
	}}, nil)
	defer close(release)
	h.submit(msg("if2", "a@example.com"))
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := h.eng.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want the context's error", err)
	}
	// The message was not settled, so it is still in the spool for the next start.
	if h.spool.(*mta.MemorySpool).Len() != 1 {
		t.Fatal("an interrupted message must stay in the spool")
	}
}

func TestAddressFamilyPreference(t *testing.T) {
	for name, tc := range map[string]struct {
		pref  mta.IPPreference
		first string
		saw6  bool
	}{
		"prefer v4": {mta.PreferIPv4, "127.0.0.1", false},
		"prefer v6": {mta.PreferIPv6, "::1", true},
		"v4 only":   {mta.IPv4Only, "127.0.0.1", false},
	} {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var tried []string
			srv, err := mtatest.Start(mtatest.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			h := newHarness(t, mtatest.Config{}, func(c *mta.Config) {
				c.IPPreference = tc.pref
				c.Dial = func(ctx context.Context, tg mta.DialTarget) (net_Conn, error) {
					mu.Lock()
					tried = append(tried, tg.Addr.String())
					mu.Unlock()
					if tg.Addr.Is6() { // this test machine need not have IPv6: pretend it is down
						return nil, errors.New("network unreachable")
					}
					return dialTCP(ctx, srv.Addr())
				}
			})
			h.res.AddMX("dual.test", mta.MX{Host: "mx.dual.test", Pref: 10})
			h.res.AddHost("mx.dual.test", "::1", "127.0.0.1")
			h.submit(msg("af", "a@dual.test"))
			h.events.waitType(t, mta.EventDelivered, 1)
			mu.Lock()
			defer mu.Unlock()
			if tried[0] != tc.first {
				t.Fatalf("first address tried = %s, want %s (all: %v)", tried[0], tc.first, tried)
			}
			saw6 := false
			for _, a := range tried {
				saw6 = saw6 || a == "::1"
			}
			if saw6 != tc.saw6 {
				t.Fatalf("IPv6 tried = %v, want %v (all: %v)", saw6, tc.saw6, tried)
			}
		})
	}

	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) { c.IPPreference = mta.IPv6Only })
	h.res.AddMX("v4.test", mta.MX{Host: "mx.v4.test", Pref: 10}).AddHost("mx.v4.test", "127.0.0.1")
	h.submit(msg("af2", "a@v4.test"))
	ev := h.events.waitType(t, mta.EventDeferred, 1)[0]
	if ev.Enhanced != "4.4.4" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestEqualPreferenceMXHostsShareTheLoad(t *testing.T) {
	var mu sync.Mutex
	counts := map[string]int{}
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) {
		c.MaxMessagesPerConn = 1 // a fresh pick for every message
		c.Dial = func(ctx context.Context, tg mta.DialTarget) (net_Conn, error) {
			mu.Lock()
			counts[tg.Host]++
			mu.Unlock()
			return dialTCP(ctx, "127.0.0.1:"+itoa(tg.Port))
		}
	})
	h.res.AddMX("lb.test", mta.MX{Host: "a.lb.test", Pref: 10}, mta.MX{Host: "b.lb.test", Pref: 10}, mta.MX{Host: "z.lb.test", Pref: 99})
	h.res.AddHost("a.lb.test", "127.0.0.1").AddHost("b.lb.test", "127.0.0.1").AddHost("z.lb.test", "127.0.0.1")
	for i := 0; i < 60; i++ {
		h.submit(msg("lb"+itoa(i), "a@lb.test"))
		h.events.waitType(t, mta.EventDelivered, i+1)
	}
	mu.Lock()
	defer mu.Unlock()
	if counts["a.lb.test"] < 10 || counts["b.lb.test"] < 10 || counts["z.lb.test"] != 0 {
		t.Fatalf("connections per MX = %v; equal preferences must share the load and a worse one must not be used", counts)
	}
}

func TestEventIDsAreStable(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, nil)
	h.submit(msg("ev1", "a@example.com", "b@example.com"))
	h.events.waitType(t, mta.EventDelivered, 2)
	ids := map[string]bool{}
	for _, e := range h.events.all() {
		ids[e.ID] = true
	}
	if !ids["ev1/0/1/DELIVERED"] || !ids["ev1/1/1/DELIVERED"] {
		t.Fatalf("event ids = %v", ids)
	}
}

// brokenData is a spool that cannot read message data.
type brokenData struct{ *mta.MemorySpool }

func (brokenData) ReadData(context.Context, string, []byte) ([]byte, error) {
	return nil, errors.New("disk on fire")
}

func TestInternalErrorEndsTheRecipientAsFailed(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) { c.Spool = brokenData{mta.NewMemorySpool()} })
	h.submit(msg("fa1", "a@example.com"))
	ev := h.events.waitType(t, mta.EventFailed, 1)[0]
	if ev.Code != 0 || !ev.Local || ev.Attempt != 1 || ev.Class.Type != mta.BounceUndetermined {
		t.Fatalf("event = %+v", ev)
	}
	if h.srv.Stats().Connections != 0 {
		t.Fatal("connected without a message to send")
	}
	if h.eng.Metrics().Failed.Load() != 1 || h.eng.Metrics().SpoolErrors.Load() != 1 {
		t.Fatalf("metrics: failed=%d spool errors=%d", h.eng.Metrics().Failed.Load(), h.eng.Metrics().SpoolErrors.Load())
	}
}

func TestAPanicInAHookEndsTheRecipientInsteadOfLoopingOrKillingTheProcess(t *testing.T) {
	boom := mta.ClassifierFunc(func(int, string, string) mta.Classification { panic("classifier bug") })
	h := newHarness(t, mtatest.Config{OnRcpt: func(string) *mtatest.Reply { return rep(550, "5.1.1", "no") }}, func(c *mta.Config) { c.Classifier = boom })
	h.submit(msg("pa1", "a@example.com"))
	ev := h.events.waitType(t, mta.EventFailed, 1)[0]
	if !strings.Contains(ev.Text, "internal error") {
		t.Fatalf("event = %+v", ev)
	}
	// The engine is still alive.
	h.submit(msg("pa2", "b@example.com"))
	h.events.waitType(t, mta.EventFailed, 2)
}

type failingSink struct{ n atomic.Int32 }

func (f *failingSink) Emit(context.Context, mta.Event) error {
	f.n.Add(1)
	return errors.New("outbox full")
}

func TestASinkThatFailsIsCountedAndDoesNotStopDelivery(t *testing.T) {
	sink := &failingSink{}
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) { c.Events = sink })
	h.submit(msg("sk1", "a@example.com"))
	if !h.srv.WaitMessages(1, 5*time.Second) {
		t.Fatal("not delivered")
	}
	if err := h.eng.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.eng.Metrics().EventErrors.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sink.n.Load() != 1 || h.eng.Metrics().EventErrors.Load() != 1 {
		t.Fatalf("sink calls=%d, event errors=%d", sink.n.Load(), h.eng.Metrics().EventErrors.Load())
	}
}

func TestMetricsAreWalkable(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, nil)
	h.submit(msg("mx1", "a@example.com"))
	h.events.waitType(t, mta.EventDelivered, 1)
	snap := h.eng.Metrics().Snapshot()
	if snap["mta_messages_submitted_total"] != 1 || snap["mta_delivered_total"] != 1 || snap["mta_transactions_total"] != 1 || snap["mta_connections_opened_total"] != 1 {
		t.Fatalf("snapshot = %v", snap)
	}
	kinds := map[string]mta.MetricKind{}
	h.eng.Metrics().Each(func(name, help string, kind mta.MetricKind, _ uint64) {
		if help == "" || !strings.HasPrefix(name, "mta_") {
			t.Errorf("metric %q has help %q", name, help)
		}
		kinds[name] = kind
	})
	if kinds["mta_pending_recipients"] != mta.KindGauge || kinds["mta_delivered_total"] != mta.KindCounter || mta.KindGauge.String() != "gauge" {
		t.Fatalf("kinds = %v", kinds)
	}
}

// The quota day follows the pool's Location: at 23:30 and at 00:30 of Sao Paulo
// the counters are one day apart, and the same instants fall on one UTC day.
func TestIPPoolDayTurnsAtMidnightOfTheLocation(t *testing.T) {
	sp, err := time.LoadLocation("America/Sao_Paulo")
	if err != nil {
		t.Skip("no time zone database:", err)
	}
	warm := mta.WarmupSchedule{Days: []int{1, 2}}
	ip := netip.MustParseAddr("192.0.2.1")
	late := time.Date(2026, 11, 20, 23, 30, 0, 0, sp) // 02:30 UTC on the 21st
	early := time.Date(2026, 11, 21, 0, 30, 0, 0, sp)

	// Located in Sao Paulo: quota used at 23:30 is fresh at 00:30.
	pools, err := mta.NewIPPools(mta.IPPoolConfig{Name: "p", Location: sp, IPs: []mta.PoolIP{
		{Addr: ip, Warmup: warm, WarmupStart: time.Date(2026, 11, 20, 0, 0, 0, 0, sp)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pools.Reserve("p", 1, late); err != nil {
		t.Fatal(err)
	}
	_, err = pools.Reserve("p", 1, late)
	var qe *mta.ErrQuotaExhausted
	if !errors.As(err, &qe) {
		t.Fatalf("day 0 allows one recipient, got %v", err)
	}
	if want := 30 * time.Minute; qe.RetryAfter != want {
		t.Fatalf("RetryAfter = %v, want %v (the next midnight of Sao Paulo)", qe.RetryAfter, want)
	}
	if _, err := pools.Reserve("p", 1, early); err != nil {
		t.Fatalf("after Sao Paulo midnight the counter must be fresh: %v", err)
	}
	if u := pools.Usage(early); len(u) != 1 || u[0].Day != 1 || u[0].Quota != 2 {
		t.Fatalf("usage at 00:30 = %+v, want warmup day 1 with quota 2", u)
	}

	// Without a Location the day is UTC, as before: 23:30 and 00:30 of Sao Paulo
	// are the same UTC day, so the quota is not fresh.
	pools, err = mta.NewIPPools(mta.IPPoolConfig{Name: "p", IPs: []mta.PoolIP{
		{Addr: ip, Warmup: warm, WarmupStart: late.UTC()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pools.Reserve("p", 1, late); err != nil {
		t.Fatal(err)
	}
	if _, err := pools.Reserve("p", 1, early); !errors.As(err, &qe) {
		t.Fatalf("UTC day is the same at 23:30 and 00:30 of Sao Paulo, got %v", err)
	}
}
