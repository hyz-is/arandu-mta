package mta

import (
	"container/heap"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// entry is a message in the engine's index: its metadata, without Data.
type entry struct {
	mu  sync.Mutex
	msg *Message
}

// Engine is the outbound delivery engine: it accepts messages, keeps them in
// the spool, and delivers them to the mail exchangers of the recipients'
// domains, retrying temporary failures until each recipient is delivered or
// bounced.
type Engine struct {
	cfg     Config
	metrics *Metrics
	spool   Spool
	res     Resolver
	pool    *connPool
	copts   clientOpts
	tenants *TenantLimiter

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	cond     *sync.Cond
	entries  map[string]*entry
	domains  map[string]*domainQ
	runq     queueRing
	timers   timerHeap
	timerSeq uint64

	state     atomic.Uint32 // 0 new, 1 started, 2 stopping, 3 stopped
	wg        sync.WaitGroup
	workersWG sync.WaitGroup
	workers   []*worker
	timerKic  chan struct{}
}

const (
	stateNew uint32 = iota
	stateStarted
	stateStopping
	stateStopped
)

// New validates the configuration and returns an engine that has not started.
func New(cfg Config) (*Engine, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.defaults()
	e := &Engine{
		cfg: cfg, metrics: cfg.Metrics, spool: cfg.Spool,
		entries:  make(map[string]*entry),
		domains:  make(map[string]*domainQ),
		timerKic: make(chan struct{}, 1),
	}
	e.cond = sync.NewCond(&e.mu)
	e.res = NewCachedResolver(cfg.Resolver, cfg.Cache, cfg.Metrics)
	e.pool = newConnPool(cfg.MaxIdlePerHost, cfg.MaxIdleTotal, cfg.IdleTimeout, cfg.Metrics)
	if cfg.Tenant.Rate > 0 || len(cfg.TenantOverrides) > 0 {
		e.tenants = NewTenantLimiter(cfg.Tenant, cfg.TenantOverrides)
	}
	e.copts = clientOpts{
		timeouts: cfg.Timeouts, port: cfg.Port, dial: cfg.Dial, rootCAs: cfg.RootCAs,
		sessions: tls.NewLRUClientSessionCache(1024), noSTARTTLS: cfg.DisableSTARTTLS,
		chunking: cfg.UseChunking, noPipelining: cfg.DisablePipelining,
		maxUses: cfg.MaxMessagesPerConn, metrics: cfg.Metrics,
	}
	return e, nil
}

// Metrics returns the engine's counters.
func (e *Engine) Metrics() *Metrics { return e.metrics }

// Start rebuilds the queue from the spool and starts the workers. ctx bounds
// only the recovery; the workers run until Shutdown. Messages
// found in the spool, from before a restart or a crash, are scheduled at their
// next due time; a message whose recipients were all settled is removed.
func (e *Engine) Start(ctx context.Context) error {
	if !e.state.CompareAndSwap(stateNew, stateStarted) {
		return errors.New("mta: engine already started")
	}
	e.ctx, e.cancel = context.WithCancel(context.Background())

	now := time.Now()
	var recovered int
	err := e.spool.Load(ctx, func(m *Message) error {
		if m.Complete() {
			if err := e.spool.Delete(ctx, m.ID); err != nil {
				e.metrics.SpoolErrors.Add(1)
			}
			return nil
		}
		for i := range m.Recipients {
			r := &m.Recipients[i]
			if r.Domain == "" {
				r.Domain, _ = DomainOf(r.Address)
			}
		}
		en := &entry{msg: m}
		e.mu.Lock()
		if _, dup := e.entries[m.ID]; dup {
			e.mu.Unlock()
			return nil
		}
		e.entries[m.ID] = en
		e.metrics.QueuedMessages.Add(1)
		e.scheduleMessageLocked(en, now)
		e.mu.Unlock()
		for i := range m.Recipients {
			if m.Recipients[i].State.Pending() {
				e.metrics.PendingRecipients.Add(1)
			}
		}
		recovered++
		return nil
	})
	if err != nil {
		e.state.Store(stateStopped)
		e.cancel()
		return fmt.Errorf("mta: recover spool: %w", err)
	}

	e.workers = make([]*worker, e.cfg.Workers)
	for i := range e.workers {
		w := &worker{e: e}
		e.workers[i] = w
		e.workersWG.Add(1)
		go w.run()
	}
	e.wg.Add(2)
	go e.timerLoop()
	go e.reapLoop()
	return nil
}

// scheduleMessageLocked schedules one item per destination domain of the
// message's pending recipients. e.mu is held.
func (e *Engine) scheduleMessageLocked(en *entry, now time.Time) {
	m := en.msg
	for i := range m.Recipients {
		r := &m.Recipients[i]
		if !r.State.Pending() {
			continue
		}
		seen := false
		for j := 0; j < i; j++ {
			if m.Recipients[j].State.Pending() && m.Recipients[j].Domain == r.Domain {
				seen = true
				break
			}
		}
		if seen {
			continue
		}
		due := r.NextAttempt
		for j := i + 1; j < len(m.Recipients); j++ {
			o := &m.Recipients[j]
			if o.State.Pending() && o.Domain == r.Domain && o.NextAttempt.Before(due) {
				due = o.NextAttempt
			}
		}
		dq := e.domainLocked(r.Domain)
		dq.items++
		e.scheduleLocked(&item{e: en, domain: r.Domain, prio: m.Priority}, dq, due, now)
	}
}

// domainLocked returns the queue of a domain, creating it. e.mu is held.
func (e *Engine) domainLocked(name string) *domainQ {
	dq := e.domains[name]
	if dq != nil {
		return dq
	}
	l := e.cfg.limitFor(name)
	dq = &domainQ{name: name, cfgMax: l.MaxConns, maxConns: l.MaxConns, perMin: l.MessagesPerMinute}
	if l.MessagesPerMinute > 0 {
		dq.burst = l.Burst
		if dq.burst <= 0 {
			dq.burst = max(1, l.MessagesPerMinute/10)
		}
		dq.bucket = NewTokenBucket(float64(l.MessagesPerMinute)/60, dq.burst)
	}
	e.domains[name] = dq
	return dq
}

// scheduleLocked puts an item in the ready queue when due, or in the timer heap
// when not. e.mu is held.
func (e *Engine) scheduleLocked(it *item, dq *domainQ, due, now time.Time) {
	if !due.After(now) {
		dq.ready[it.prio].push(it)
		dq.nready++
		e.kickLocked(dq, now)
		return
	}
	e.timerSeq++
	if e.timers.add(timerEntry{at: due, seq: e.timerSeq, it: it, dq: dq}) {
		select {
		case e.timerKic <- struct{}{}:
		default:
		}
	}
}

// kickLocked hands the domain to workers while it has ready items and room for
// more connections. e.mu is held.
func (e *Engine) kickLocked(dq *domainQ, now time.Time) {
	if e.state.Load() >= stateStopping || dq.nready == 0 {
		return
	}
	if now.Before(dq.pausedUntil) {
		e.wakeLocked(dq, dq.pausedUntil)
		return
	}
	want := min(dq.nready, dq.maxConns) - dq.active - dq.tokens
	for ; want > 0; want-- {
		dq.tokens++
		e.runq.push(dq)
		e.cond.Signal()
	}
}

// wakeLocked arranges for the domain to be kicked at the given time.
func (e *Engine) wakeLocked(dq *domainQ, at time.Time) {
	if !dq.wakeAt.IsZero() && !dq.wakeAt.After(at) {
		return
	}
	dq.wakeAt = at
	e.timerSeq++
	if e.timers.add(timerEntry{at: at, seq: e.timerSeq, dq: dq}) {
		select {
		case e.timerKic <- struct{}{}:
		default:
		}
	}
}

// timerLoop moves due items to their domain's ready queue.
func (e *Engine) timerLoop() {
	defer e.wg.Done()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		e.mu.Lock()
		now := time.Now()
		for len(e.timers) > 0 && !e.timers[0].at.After(now) {
			t := heap.Pop(&e.timers).(timerEntry)
			if t.it != nil {
				t.dq.ready[t.it.prio].push(t.it)
				t.dq.nready++
			} else if !t.dq.wakeAt.After(t.at) {
				t.dq.wakeAt = time.Time{}
			}
			e.kickLocked(t.dq, now)
		}
		var wait time.Duration = time.Hour
		if len(e.timers) > 0 {
			wait = max(time.Until(e.timers[0].at), time.Millisecond)
		}
		stopping := e.state.Load() >= stateStopping
		e.mu.Unlock()
		if stopping {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
		select {
		case <-timer.C:
		case <-e.timerKic:
		case <-e.ctx.Done():
			return
		}
	}
}

func (e *Engine) reapLoop() {
	defer e.wg.Done()
	t := time.NewTicker(max(e.cfg.IdleTimeout/2, 50*time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-t.C:
			e.pool.reap(time.Now())
		case <-e.ctx.Done():
			return
		}
	}
}

// nextRunnable blocks until a domain needs a worker, or the engine stops.
func (e *Engine) nextRunnable() *domainQ {
	e.mu.Lock()
	defer e.mu.Unlock()
	for e.runq.len() == 0 || e.state.Load() >= stateStopping {
		if e.state.Load() >= stateStopping {
			return nil
		}
		e.cond.Wait()
	}
	dq := e.runq.pop()
	dq.tokens--
	dq.active++
	return dq
}

// takeLocked removes the next item the domain may start, or returns nil and
// arranges a wake-up when a pause or the rate limit holds it back. e.mu is held.
func (e *Engine) takeLocked(dq *domainQ, now time.Time) *item {
	if dq.nready == 0 {
		return nil
	}
	if now.Before(dq.pausedUntil) {
		e.wakeLocked(dq, dq.pausedUntil)
		return nil
	}
	if dq.bucket != nil {
		if dq.level > 0 {
			dq.bucket.SetRate(float64(dq.perMin)/60/float64(uint(1)<<uint(dq.level)), now)
		}
		if ok, wait := dq.bucket.Take(now, 1); !ok {
			e.wakeLocked(dq, now.Add(wait))
			return nil
		}
	}
	for p := 0; p < priorityLevels; p++ {
		if it := dq.ready[p].pop(); it != nil {
			dq.nready--
			return it
		}
	}
	return nil
}

// releaseLocked is called when a worker leaves a domain. e.mu is held.
func (e *Engine) releaseLocked(dq *domainQ, now time.Time) {
	dq.active--
	e.kickLocked(dq, now)
	if dq.items == 0 && dq.active == 0 && dq.tokens == 0 && dq.level == 0 && now.After(dq.pausedUntil) && dq.wakeAt.IsZero() {
		delete(e.domains, dq.name)
	}
}

// throttle backs a domain off after a reply that asked the sender to slow down.
func (e *Engine) throttle(dq *domainQ, now time.Time) {
	a := e.cfg.Adaptive
	e.mu.Lock()
	defer e.mu.Unlock()
	if dq.level < a.MaxLevel {
		dq.level++
	}
	dq.calm = 0
	dq.maxConns = max(1, dq.cfgMax>>uint(dq.level))
	pause := a.BasePause << uint(dq.level-1)
	if pause <= 0 || pause > a.MaxPause {
		pause = a.MaxPause
	}
	if until := now.Add(pause); until.After(dq.pausedUntil) {
		dq.pausedUntil = until
	}
	e.metrics.Throttled.Add(1)
}

// clean records a transaction that raised no complaint and lets a throttled
// domain recover.
func (e *Engine) clean(dq *domainQ, now time.Time) {
	if dq.level == 0 { // racy read is fine: a stale zero only delays recovery by one call
		return
	}
	a := e.cfg.Adaptive
	e.mu.Lock()
	defer e.mu.Unlock()
	if dq.level == 0 || now.Before(dq.pausedUntil) {
		return
	}
	dq.calm++
	if dq.calm >= a.RecoverAfter {
		dq.calm = 0
		dq.level--
		dq.maxConns = max(1, dq.cfgMax>>uint(dq.level))
		e.kickLocked(dq, now)
	}
}

// SignError is returned by Submit when the Signer failed; Err is its error.
type SignError struct{ Err error }

// Error implements error.
func (e *SignError) Error() string { return "mta: signing failed: " + e.Err.Error() }

// Unwrap returns the Signer's error.
func (e *SignError) Unwrap() error { return e.Err }

// Submit accepts a message. When it returns nil the message is in the spool
// and delivery is scheduled; the message passed in is not retained.
//
// Submit returns ErrInvalidMessage or ErrInvalidAddress wrapped for a message
// the wire protocol cannot carry, ErrDuplicate when the ID is already queued,
// *TenantLimitError when the tenant is over its rate, *SignError when the
// Signer failed, and ErrClosed once the engine is shutting down.
func (e *Engine) Submit(ctx context.Context, m *Message) error {
	switch e.state.Load() {
	case stateNew:
		return ErrNotStarted
	case stateStarted:
	default:
		return ErrClosed
	}
	msg, err := e.prepare(m)
	if err != nil {
		e.metrics.SubmitRejected.Add(1)
		return err
	}
	if err := e.tenants.Allow(msg.Tenant, len(msg.Recipients), time.Now()); err != nil {
		e.metrics.TenantLimited.Add(1)
		return err
	}
	data := m.Data
	if msg.DKIMDomain != "" && e.cfg.Signer != nil {
		signed, err := e.cfg.Signer.Sign(ctx, msg.DKIMDomain, data)
		if err != nil {
			e.metrics.SubmitRejected.Add(1)
			return &SignError{Err: err}
		}
		if len(signed) > e.cfg.MaxMessageSize {
			e.metrics.SubmitRejected.Add(1)
			return fmt.Errorf("%w: signed message exceeds %d bytes", ErrInvalidMessage, e.cfg.MaxMessageSize)
		}
		data = signed
	}

	en := &entry{msg: msg}
	e.mu.Lock()
	if _, dup := e.entries[msg.ID]; dup {
		e.mu.Unlock()
		return ErrDuplicate
	}
	e.entries[msg.ID] = en
	e.mu.Unlock()

	toPut := *msg
	toPut.Data = data
	if err := e.spool.Put(ctx, &toPut); err != nil {
		e.mu.Lock()
		delete(e.entries, msg.ID)
		e.mu.Unlock()
		if !errors.Is(err, ErrDuplicate) {
			e.metrics.SpoolErrors.Add(1)
		}
		return err
	}
	msg.Size = len(data)

	e.metrics.MessagesSubmitted.Add(1)
	e.metrics.RecipientsSubmitted.Add(uint64(len(msg.Recipients)))
	e.metrics.BytesSubmitted.Add(uint64(len(data)))
	e.metrics.PendingRecipients.Add(int64(len(msg.Recipients)))
	e.metrics.QueuedMessages.Add(1)

	e.mu.Lock()
	e.scheduleMessageLocked(en, time.Now())
	e.mu.Unlock()
	return nil
}

// prepare validates a message and makes the engine's own copy of its metadata.
func (e *Engine) prepare(m *Message) (*Message, error) {
	if m == nil || !ValidID(m.ID) {
		return nil, fmt.Errorf("%w: bad id", ErrInvalidMessage)
	}
	if len(m.Data) == 0 {
		return nil, fmt.Errorf("%w: no data", ErrInvalidMessage)
	}
	if len(m.Data) > e.cfg.MaxMessageSize {
		return nil, fmt.Errorf("%w: data exceeds %d bytes", ErrInvalidMessage, e.cfg.MaxMessageSize)
	}
	if len(m.Recipients) == 0 || len(m.Recipients) > e.cfg.MaxRecipients {
		return nil, fmt.Errorf("%w: need 1 to %d recipients", ErrInvalidMessage, e.cfg.MaxRecipients)
	}
	if m.Priority >= priorityLevels {
		return nil, fmt.Errorf("%w: bad priority", ErrInvalidMessage)
	}
	if m.MailFrom != "" {
		if err := ValidAddress(m.MailFrom); err != nil {
			return nil, fmt.Errorf("mail from: %w", err)
		}
	}
	now := time.Now()
	msg := &Message{
		ID: m.ID, Tenant: m.Tenant, MailFrom: m.MailFrom, Priority: m.Priority,
		IPPool: m.IPPool, DKIMDomain: m.DKIMDomain, Size: len(m.Data),
		CreatedAt: now, ExpiresAt: now.Add(e.cfg.Expiry),
		Recipients: make([]Recipient, 0, len(m.Recipients)),
	}
	if !m.ExpiresAt.IsZero() {
		msg.ExpiresAt = m.ExpiresAt
	}
	// Duplicates are dropped. A message has a few recipients, so a scan beats a
	// map; a large one pays for the map.
	var seen map[string]struct{}
	if len(m.Recipients) > 16 {
		seen = make(map[string]struct{}, len(m.Recipients))
	}
	for _, r := range m.Recipients {
		if err := ValidAddress(r.Address); err != nil {
			return nil, fmt.Errorf("recipient %q: %w", r.Address, err)
		}
		if seen != nil {
			key := strings.ToLower(r.Address)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
		} else if hasRecipient(msg.Recipients, r.Address) {
			continue
		}
		d, _ := DomainOf(r.Address)
		msg.Recipients = append(msg.Recipients, Recipient{Address: r.Address, Domain: d, NextAttempt: now})
	}
	msg.NextAttempt = now
	return msg, nil
}

func hasRecipient(list []Recipient, addr string) bool {
	for i := range list {
		if strings.EqualFold(list[i].Address, addr) {
			return true
		}
	}
	return false
}

// CancelResult says what Cancel did.
type CancelResult struct {
	// Cancelled is the recipients that will not be attempted.
	Cancelled int
	// InFlight is the recipients whose transaction is running; they cannot be
	// stopped and will settle normally.
	InFlight int
	// Settled is the recipients that already had a final outcome.
	Settled int
}

// Cancel stops the delivery of everything not yet delivered. It returns
// ErrNotFound for an unknown or completed message and ErrNotCancellable when
// every recipient was already settled or is being delivered right now.
func (e *Engine) Cancel(ctx context.Context, id string) (CancelResult, error) {
	e.mu.Lock()
	en := e.entries[id]
	e.mu.Unlock()
	if en == nil {
		return CancelResult{}, ErrNotFound
	}
	var res CancelResult
	en.mu.Lock()
	now := time.Now()
	for i := range en.msg.Recipients {
		r := &en.msg.Recipients[i]
		switch {
		case r.State.Pending():
			r.State = StateCancelled
			r.UpdatedAt = now
			res.Cancelled++
		case r.State == StateSending:
			res.InFlight++
		default:
			res.Settled++
		}
	}
	if res.Cancelled == 0 {
		en.mu.Unlock()
		return res, ErrNotCancellable
	}
	en.msg.recompute()
	complete := en.msg.Complete()
	if complete {
		if err := e.spool.Delete(ctx, id); err != nil {
			e.metrics.SpoolErrors.Add(1)
		}
	} else if err := e.spool.Update(ctx, en.msg); err != nil {
		e.metrics.SpoolErrors.Add(1)
	}
	en.mu.Unlock()
	e.metrics.Cancelled.Add(uint64(res.Cancelled))
	e.metrics.PendingRecipients.Add(-int64(res.Cancelled))
	if complete {
		e.removeEntry(id)
	}
	return res, nil
}

func (e *Engine) removeEntry(id string) {
	e.mu.Lock()
	if _, ok := e.entries[id]; ok {
		delete(e.entries, id)
		e.metrics.QueuedMessages.Add(-1)
	}
	e.mu.Unlock()
}

// Message returns a snapshot of a queued message, without its data.
func (e *Engine) Message(id string) (*Message, bool) {
	e.mu.Lock()
	en := e.entries[id]
	e.mu.Unlock()
	if en == nil {
		return nil, false
	}
	en.mu.Lock()
	defer en.mu.Unlock()
	return en.msg.Clone(), true
}

// DomainStats describes the queue of one destination domain.
type DomainStats struct {
	Domain string
	// Ready are items waiting for a connection, Delayed items waiting for their
	// retry time, Active the connections in use.
	Ready, Delayed, Active int
	// MaxConns is the connection limit now, lowered while the domain throttles.
	MaxConns int
	// Level is how many times the domain has been backed off, 0 when healthy.
	Level int
	// PausedUntil is the end of the pause after a throttling reply; zero when
	// none is in force.
	PausedUntil time.Time
}

// TenantStats describes what a tenant has in the queue.
type TenantStats struct {
	Tenant string
	// Messages is the queued messages and Pending the recipients still waiting.
	Messages, Pending int
}

// Stats is a point-in-time view of the queue.
type Stats struct {
	Messages          int
	PendingRecipients int
	Ready, Delayed    int
	Domains           []DomainStats
	Tenants           []TenantStats
}

// Stats reports the queue by domain and by tenant. It walks the queue, so it is
// for dashboards, not for hot paths.
func (e *Engine) Stats() Stats {
	now := time.Now()
	e.mu.Lock()
	s := Stats{Messages: len(e.entries)}
	for _, dq := range e.domains {
		ds := DomainStats{
			Domain: dq.name, Ready: dq.nready, Active: dq.active,
			Delayed:  max(0, dq.items-dq.nready-dq.active),
			MaxConns: dq.maxConns, Level: dq.level,
		}
		if now.Before(dq.pausedUntil) {
			ds.PausedUntil = dq.pausedUntil
		}
		s.Ready += ds.Ready
		s.Delayed += ds.Delayed
		s.Domains = append(s.Domains, ds)
	}
	ents := make([]*entry, 0, len(e.entries))
	for _, en := range e.entries {
		ents = append(ents, en)
	}
	e.mu.Unlock()

	byTenant := map[string]*TenantStats{}
	for _, en := range ents {
		en.mu.Lock()
		ts := byTenant[en.msg.Tenant]
		if ts == nil {
			ts = &TenantStats{Tenant: en.msg.Tenant}
			byTenant[en.msg.Tenant] = ts
		}
		ts.Messages++
		for i := range en.msg.Recipients {
			if st := en.msg.Recipients[i].State; st.Pending() || st == StateSending {
				ts.Pending++
				s.PendingRecipients++
			}
		}
		en.mu.Unlock()
	}
	for _, ts := range byTenant {
		s.Tenants = append(s.Tenants, *ts)
	}
	sort.Slice(s.Domains, func(i, j int) bool { return s.Domains[i].Domain < s.Domains[j].Domain })
	sort.Slice(s.Tenants, func(i, j int) bool { return s.Tenants[i].Tenant < s.Tenants[j].Tenant })
	return s
}

// Drain waits until every queued message has been settled, or ctx ends. It does
// not stop intake: it is for tests and for a node that has stopped receiving.
func (e *Engine) Drain(ctx context.Context) error {
	t := time.NewTicker(2 * time.Millisecond)
	defer t.Stop()
	for {
		e.mu.Lock()
		n := len(e.entries)
		e.mu.Unlock()
		if n == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Shutdown stops intake, lets the transactions already running finish, closes
// the idle connections, and returns. Messages still queued stay in the spool and
// are picked up by the next Start. If ctx ends first, the running transactions
// are cut off and Shutdown returns ctx.Err(). It does not close the spool.
func (e *Engine) Shutdown(ctx context.Context) error {
	// A second call, or one that races the first, waits for the same shutdown.
	for started := false; !started; {
		switch e.state.Load() {
		case stateNew:
			if e.state.CompareAndSwap(stateNew, stateStopped) {
				return nil
			}
		case stateStarted:
			started = e.state.CompareAndSwap(stateStarted, stateStopping)
		default:
			started = true
		}
	}
	e.mu.Lock()
	e.cond.Broadcast()
	e.mu.Unlock()
	select {
	case e.timerKic <- struct{}{}:
	default:
	}

	done := make(chan struct{})
	go func() {
		// Workers leave once their current transaction ends; the timer and the
		// reaper leave when the context is cancelled.
		e.workersWG.Wait()
		e.cancel()
		e.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		e.abortConnections()
		e.cancel()
		<-done
		e.pool.closeAll()
		e.state.Store(stateStopped)
		return ctx.Err()
	}
	e.pool.closeAll()
	e.state.Store(stateStopped)
	return nil
}

// abortConnections closes the connections of running transactions.
func (e *Engine) abortConnections() {
	for _, w := range e.workers {
		if c := w.cur.Load(); c != nil {
			_ = c.nc.Close()
		}
	}
}
