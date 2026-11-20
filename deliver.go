package mta

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"
)

type outKind uint8

const (
	okDelivered outKind = iota + 1
	okDeferred
	okBounced
	okFailed
)

// outcome is what became of one recipient in one attempt.
type outcome struct {
	kind       outKind
	reply      Reply
	mx         string
	class      Classification
	attempted  bool // counts toward the recipient's attempts
	expired    bool
	suppressed bool
}

// worker delivers items. Its slices are reused from one item to the next, so a
// transaction on the hot path allocates only what the replies and the events
// need.
type worker struct {
	e   *Engine
	cur atomic.Pointer[smtpConn]

	idx     []int
	prev    []RecipientState
	addrs   []string
	rcpts   []string
	pos     []int // positions in idx that are sent to the server
	replies []Reply
	out     []outcome
	data    []byte
	events  []Event
	addrBuf []netip.Addr
	mx      []MX
}

const itemsPerVisit = 64

func (w *worker) run() {
	e := w.e
	defer e.workersWG.Done()
	for {
		dq := e.nextRunnable()
		if dq == nil {
			return
		}
		for n := 0; n < itemsPerVisit && e.state.Load() < stateStopping; n++ {
			e.mu.Lock()
			it := e.takeLocked(dq, time.Now())
			e.mu.Unlock()
			if it == nil {
				break
			}
			w.process(dq, it)
		}
		e.mu.Lock()
		e.releaseLocked(dq, time.Now())
		e.mu.Unlock()
	}
}

// process runs one item: claim the recipients, check them, deliver, settle.
func (w *worker) process(dq *domainQ, it *item) {
	e := w.e
	e.metrics.ActiveWorkers.Add(1)
	defer e.metrics.ActiveWorkers.Add(-1)
	defer func() {
		if r := recover(); r != nil {
			e.metrics.Failed.Add(1)
			w.panicked(it, r)
		}
	}()
	ctx := e.ctx
	en := it.e
	now := time.Now()

	// Claim the pending recipients of this domain.
	en.mu.Lock()
	m := en.msg
	w.idx, w.prev, w.addrs = w.idx[:0], w.prev[:0], w.addrs[:0]
	for i := range m.Recipients {
		r := &m.Recipients[i]
		if r.Domain == it.domain && r.State.Pending() {
			w.idx = append(w.idx, i)
			w.prev = append(w.prev, r.State)
			w.addrs = append(w.addrs, r.Address)
			r.State = StateSending
		}
	}
	id, tenant, mailFrom, pool, expires := m.ID, m.Tenant, m.MailFrom, m.IPPool, m.ExpiresAt
	en.mu.Unlock()

	if len(w.idx) == 0 {
		e.finishItem(dq)
		return
	}
	n := len(w.idx)
	w.out = growOutcomes(w.out, n)
	for k := range w.out {
		w.out[k] = outcome{}
	}

	// The retry window may have closed while the message waited.
	if !now.Before(expires) {
		w.expireAll(it)
		w.settle(dq, it, now, false)
		return
	}

	// Suppression.
	w.pos = w.pos[:0]
	for k := 0; k < n; k++ {
		if e.cfg.Suppression != nil {
			if sup, reason := e.cfg.Suppression.Suppressed(ctx, tenant, w.addrs[k]); sup {
				text := "recipient is on the suppression list"
				if reason != "" {
					text += ": " + reason
				}
				w.out[k] = outcome{
					kind: okBounced, reply: localReply(550, "5.1.1", text), suppressed: true,
					class: Classification{Permanent: true, Type: BouncePermanent, SubType: SubSuppressed},
				}
				continue
			}
		}
		w.pos = append(w.pos, k)
	}
	if len(w.pos) == 0 {
		w.settle(dq, it, now, false)
		return
	}

	// Cluster-wide limit.
	if lim := e.cfg.Distributed; lim != nil {
		ok, retry, err := lim.Allow(ctx, "domain:"+it.domain, len(w.pos))
		switch {
		case err != nil:
			e.metrics.LimiterErrors.Add(1)
		case !ok:
			e.metrics.LimiterDenied.Add(1)
			w.requeue(dq, it, now, retry)
			return
		}
	}

	// Source address.
	lease, err := e.cfg.IPs.Reserve(pool, len(w.pos), now)
	if err != nil {
		var qe *ErrQuotaExhausted
		if errors.As(err, &qe) {
			e.metrics.QuotaExhausted.Add(1)
			w.requeue(dq, it, now, min(qe.RetryAfter, time.Minute))
			return
		}
		w.failAll(err.Error())
		w.settle(dq, it, now, false)
		return
	}

	// The message body.
	var derr error
	w.data, derr = e.spool.ReadData(ctx, id, w.data[:0])
	if derr != nil {
		e.metrics.SpoolErrors.Add(1)
		lease.Release()
		w.failAll("message data unavailable: " + derr.Error())
		w.settle(dq, it, now, false)
		return
	}

	w.deliver(ctx, dq, it, lease, mailFrom, tenant)
	w.settle(dq, it, now, true)
}

func growOutcomes(s []outcome, n int) []outcome {
	if cap(s) < n {
		return make([]outcome, n, n+n/2)
	}
	return s[:n]
}

// deliver resolves the exchangers and runs the transaction, filling w.out for
// the recipients at w.pos.
func (w *worker) deliver(ctx context.Context, dq *domainQ, it *item, lease *IPLease, mailFrom, tenant string) {
	e := w.e
	hosts, err := resolveMX(ctx, e.res, it.domain, e.cfg.MaxMXHosts, w.mx[:0])
	if err != nil {
		lease.Release()
		w.dnsFailure(it.domain, err)
		return
	}

	w.mx = hosts
	var pol *MTASTSPolicy
	if src := e.cfg.MTASTS; src != nil {
		p, perr := src.Policy(ctx, it.domain)
		if perr != nil {
			e.metrics.MTASTSErrors.Add(1)
		} else {
			pol = p
		}
	}
	strict := pol != nil && pol.Mode == MTASTSEnforce
	if strict {
		e.metrics.MTASTSEnforced.Add(1)
	}

	var local netip.Addr
	ehlo := e.cfg.EHLOName
	if lease != nil {
		local = lease.Addr
		if lease.EHLOName != "" {
			ehlo = lease.EHLOName
		}
	}

	rcpts := w.rcptBuf()
	t := txn{mailFrom: mailFrom, rcpts: rcpts, data: w.data}
	if cap(w.replies) < len(rcpts) {
		w.replies = make([]Reply, len(rcpts), len(rcpts)+len(rcpts)/2)
	}
	w.replies = w.replies[:len(rcpts)]

	var (
		lastFail    Reply
		haveFail    bool
		sawTemp     bool
		notFound    int
		reachedMX   string
		transacted  bool
		anyResolved bool
	)
	for _, h := range hosts {
		if strict && !pol.MatchesMX(h.Host) {
			e.metrics.MTASTSRejectedMX.Add(1)
			lastFail, haveFail = localReply(451, "4.7.5", "mail exchanger "+h.Host+" is not allowed by the MTA-STS policy of "+it.domain), true
			continue
		}
		ans, aerr := e.res.LookupAddr(ctx, h.Host)
		if aerr != nil {
			if errors.Is(aerr, ErrNameNotFound) {
				notFound++
			} else {
				sawTemp = true
			}
			lastFail, haveFail = localReply(451, "4.4.3", "cannot resolve mail exchanger "+h.Host+": "+aerr.Error()), true
			continue
		}
		anyResolved = true
		w.addrBuf = orderAddrs(w.addrBuf, ans.Addrs, e.cfg.IPPreference, local)
		if len(w.addrBuf) == 0 {
			lastFail, haveFail = localReply(451, "4.4.4", "mail exchanger "+h.Host+" has no address this node can reach"), true
			continue
		}
		for ai, a := range w.addrBuf {
			if ai >= 2 {
				break
			}
			done, fail := w.viaAddr(ctx, h.Host, a, local, ehlo, strict, &t)
			if done {
				transacted, reachedMX = true, h.Host
				break
			}
			lastFail, haveFail = fail, true
		}
		if transacted {
			break
		}
	}

	if !transacted {
		lease.Release()
		switch {
		case !haveFail:
			w.failTemp(localReply(451, "4.4.1", "no mail exchanger could be tried for "+it.domain), "")
		case !anyResolved && !sawTemp && notFound > 0 && notFound == len(hosts):
			w.permanent(localReply(550, "5.4.4", "no address found for any mail exchanger of "+it.domain), SubNoEmail)
		default:
			w.failTemp(lastFail, "")
		}
		return
	}

	// Translate the replies of the transaction.
	for pi, k := range w.pos {
		w.out[k] = w.fromReply(w.replies[pi], reachedMX)
	}
}

// rcptBuf fills the recipient addresses of the transaction from w.pos.
func (w *worker) rcptBuf() []string {
	w.rcpts = w.rcpts[:0]
	for _, k := range w.pos {
		w.rcpts = append(w.rcpts, w.addrs[k])
	}
	return w.rcpts
}

// viaAddr runs the transaction against one address of an exchanger, reusing an
// idle connection when there is one. done is false when the exchanger could not
// take the transaction; fail then says why.
func (w *worker) viaAddr(ctx context.Context, host string, addr, local netip.Addr, ehlo string, strict bool, t *txn) (done bool, fail Reply) {
	e := w.e
	o := &e.copts
	key := poolKey{host: host, addr: addr, local: local, strict: strict}
	c := e.pool.get(key, time.Now())
	reused := c != nil
	if reused {
		e.metrics.ConnectionsReused.Add(1)
	}
	for {
		if c == nil {
			var cf *connFailure
			c, cf = connect(ctx, o, host, addr, local, ehlo, strict)
			if cf != nil {
				return false, cf.reply
			}
		}
		w.cur.Store(c)
		e.metrics.Transactions.Add(1)
		st, why, err := c.transact(t, w.replies, o)
		w.cur.Store(nil)
		switch st {
		case txDone:
			if c.broken || c.uses >= o.maxUses || !e.pool.put(c, time.Now()) {
				c.quit()
			}
			return true, Reply{}
		case txStale:
			e.metrics.ConnectionsStale.Add(1)
			c.close()
			if reused {
				reused, c = false, nil
				continue
			}
			fallthrough
		default:
			c.close()
			if why.Code != 0 {
				return false, why
			}
			text := "transaction with " + host + " failed"
			if err != nil {
				text += ": " + err.Error()
			}
			return false, localReply(451, "4.4.2", text)
		}
	}
}

// fromReply turns a final SMTP reply into an outcome.
func (w *worker) fromReply(r Reply, mx string) outcome {
	e := w.e
	o := outcome{reply: r, mx: mx, attempted: true}
	if r.Code/100 == 2 {
		o.kind = okDelivered
		return o
	}
	o.class = e.cfg.Classifier.Classify(r.Code, r.Enhanced, r.Text)
	if o.class.Permanent {
		o.kind = okBounced
	} else {
		o.kind = okDeferred
	}
	return o
}

func (w *worker) failTemp(r Reply, mx string) {
	class := Classification{Type: BounceTransient, SubType: SubGeneral}
	if !r.Local {
		// A refusal from a server is read by the classifier, for the throttling it
		// may ask for, but it ends in a retry whatever the code says: no exchanger
		// was reached.
		class = w.e.cfg.Classifier.Classify(r.Code, r.Enhanced, r.Text)
		class.Permanent = false
		if class.Type == BouncePermanent {
			class.Type = BounceTransient
		}
	}
	for _, k := range w.pos {
		w.out[k] = outcome{kind: okDeferred, reply: r, mx: mx, attempted: true, class: class}
	}
}

func (w *worker) permanent(r Reply, sub BounceSubType) {
	for _, k := range w.pos {
		w.out[k] = outcome{
			kind: okBounced, reply: r, attempted: true,
			class: Classification{Permanent: true, Type: BouncePermanent, SubType: sub},
		}
	}
}

// failAll ends every recipient at w.pos with an internal error.
func (w *worker) failAll(text string) {
	for _, k := range w.pos {
		w.out[k] = outcome{kind: okFailed, reply: localReply(0, "", text), attempted: true,
			class: Classification{Type: BounceUndetermined, SubType: SubGeneral}}
	}
}

func (w *worker) dnsFailure(domain string, err error) {
	e := w.e
	switch {
	case errors.Is(err, ErrNullMX):
		e.metrics.NullMX.Add(1)
		w.permanent(localReply(556, "5.1.10", domain+" does not accept mail (null MX)"), SubGeneral)
	case errors.Is(err, ErrNameNotFound):
		w.permanent(localReply(550, "5.1.2", "domain "+domain+" does not exist: no MX, A or AAAA record"), SubNoEmail)
	default:
		w.failTemp(localReply(451, "4.4.3", "temporary DNS failure resolving "+domain+": "+err.Error()), "")
	}
}

// expireAll bounces every claimed recipient: the retry window is over.
func (w *worker) expireAll(it *item) {
	en := it.e
	en.mu.Lock()
	for k, i := range w.idx {
		r := &en.msg.Recipients[i]
		w.out[k] = expiredOutcome(r)
	}
	en.mu.Unlock()
	w.pos = w.pos[:0]
}

func expiredOutcome(r *Recipient) outcome {
	rep := localReply(r.LastCode, r.LastEnhanced, "delivery time expired")
	if rep.Code == 0 {
		rep.Code = 554
	}
	if rep.Enhanced == "" {
		rep.Enhanced = "5.4.7"
	}
	if r.LastText != "" {
		rep.Text += "; last reply: " + r.LastText
	}
	return outcome{
		kind: okBounced, reply: rep, mx: r.LastMX, expired: true,
		class: Classification{Type: BounceTransient, SubType: SubGeneral},
	}
}

// requeue puts the claimed recipients back as they were and schedules the item
// again after wait, without counting an attempt.
func (w *worker) requeue(dq *domainQ, it *item, now time.Time, wait time.Duration) {
	e := w.e
	en := it.e
	en.mu.Lock()
	for k, i := range w.idx {
		if r := &en.msg.Recipients[i]; r.State == StateSending {
			r.State = w.prev[k]
		}
	}
	en.mu.Unlock()
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	e.mu.Lock()
	e.scheduleLocked(it, dq, now.Add(wait), now)
	e.mu.Unlock()
}

func (e *Engine) finishItem(dq *domainQ) {
	e.mu.Lock()
	dq.items--
	e.mu.Unlock()
}

// panicked settles an item whose processing panicked: the recipients it had
// claimed end as failed, so a bug never loops on a message.
func (w *worker) panicked(it *item, v any) {
	text := "internal error"
	if err, ok := v.(error); ok {
		text += ": " + err.Error()
	}
	w.pos = w.pos[:0]
	for k := range w.idx {
		w.pos = append(w.pos, k)
	}
	w.out = growOutcomes(w.out, len(w.idx))
	w.failAll(text)
	e := w.e
	e.mu.Lock()
	dq := e.domains[it.domain]
	e.mu.Unlock()
	if dq == nil {
		return
	}
	w.settle(dq, it, time.Now(), false)
}

// settle writes the outcomes into the message, persists the new state, sends
// the events, and schedules what is left.
func (w *worker) settle(dq *domainQ, it *item, now time.Time, ranTransaction bool) {
	e := w.e
	ctx := e.ctx
	en := it.e
	w.events = w.events[:0]
	var (
		delivered, deferredN, bounced, failedN, expiredN, suppressedN, terminal int
		throttled, cleanTx                                                      bool
		due                                                                     time.Time
		complete                                                                bool
	)
	cleanTx = ranTransaction

	en.mu.Lock()
	m := en.msg
	for k, i := range w.idx {
		r := &m.Recipients[i]
		o := &w.out[k]
		if o.kind == 0 {
			// Never classified: nothing happened for this recipient; put it back.
			r.State = w.prev[k]
			continue
		}
		if o.attempted {
			r.Attempts++
		}
		r.LastCode, r.LastEnhanced, r.LastText, r.UpdatedAt = o.reply.Code, o.reply.Enhanced, o.reply.Text, now
		if o.mx != "" {
			r.LastMX = o.mx
		}
		evType := EventType(0)
		switch o.kind {
		case okDelivered:
			r.State, r.NextAttempt = StateDelivered, time.Time{}
			evType = EventDelivered
			delivered++
			terminal++
		case okBounced:
			r.State, r.NextAttempt = StateBounced, time.Time{}
			evType = EventBounced
			bounced++
			terminal++
			if o.expired {
				expiredN++
			}
			if o.suppressed {
				suppressedN++
			}
		case okFailed:
			r.State, r.NextAttempt = StateFailed, time.Time{}
			evType = EventFailed
			failedN++
			terminal++
		case okDeferred:
			wait := e.cfg.Backoff.Delay(r.Attempts)
			next := now.Add(wait)
			if !next.Before(m.ExpiresAt) {
				// No retry fits in the window: this is the last word.
				exp := expiredOutcome(r)
				exp.reply.Code, exp.reply.Enhanced = o.reply.Code, firstNonEmpty(o.reply.Enhanced, "5.4.7")
				exp.reply.Text = "delivery time expired; last reply: " + o.reply.Text
				exp.reply.Local = true
				exp.mx = o.mx
				*o = exp
				r.State, r.NextAttempt = StateBounced, time.Time{}
				r.LastCode, r.LastEnhanced, r.LastText = o.reply.Code, o.reply.Enhanced, o.reply.Text
				evType = EventBounced
				bounced++
				expiredN++
				terminal++
				break
			}
			r.State, r.NextAttempt = StateDeferred, next
			if due.IsZero() || next.Before(due) {
				due = next
			}
			evType = EventDeferred
			deferredN++
			if o.class.Throttle {
				throttled = true
			}
		}
		ev := Event{
			Type: evType, MessageID: m.ID, Tenant: m.Tenant, Recipient: r.Address, Time: now,
			Attempt: r.Attempts, Code: o.reply.Code, Enhanced: o.reply.Enhanced, Text: o.reply.Text,
			MX: o.mx, Local: o.reply.Local, Class: o.class, Expired: o.expired, Suppressed: o.suppressed,
		}
		if evType == EventDeferred {
			ev.NextAttempt = r.NextAttempt
		}
		ev.ID = m.ID + "/" + strconv.Itoa(i) + "/" + strconv.Itoa(r.Attempts) + "/" + evType.String()
		w.events = append(w.events, ev)
	}
	m.Attempts++
	m.recompute()
	complete = m.Complete()

	// Persist before announcing. The common case, everything delivered in one
	// go, is a single delete.
	var perr error
	switch {
	case complete:
		perr = e.spool.Delete(ctx, m.ID)
		if perr != nil {
			// Leave the terminal state on disk so a restart does not deliver again.
			perr = e.spool.Update(ctx, m)
		}
	case len(w.events) > 0:
		perr = e.spool.Update(ctx, m)
	}
	if perr != nil {
		e.metrics.SpoolErrors.Add(1)
	}
	// The remaining pending recipients of this domain, and when.
	var again bool
	var againDue time.Time
	for i := range m.Recipients {
		r := &m.Recipients[i]
		if r.Domain == it.domain && r.State.Pending() {
			if !again || r.NextAttempt.Before(againDue) {
				againDue = r.NextAttempt
			}
			again = true
		}
	}
	en.mu.Unlock()

	e.metrics.Delivered.Add(uint64(delivered))
	e.metrics.Deferred.Add(uint64(deferredN))
	e.metrics.Bounced.Add(uint64(bounced))
	e.metrics.Failed.Add(uint64(failedN))
	e.metrics.Expired.Add(uint64(expiredN))
	e.metrics.Suppressed.Add(uint64(suppressedN))
	e.metrics.PendingRecipients.Add(-int64(terminal))

	if complete {
		e.removeEntry(m.ID)
	}

	if throttled {
		e.throttle(dq, now)
	} else if cleanTx && deferredN == 0 {
		e.clean(dq, now)
	}

	if again {
		if againDue.IsZero() {
			againDue = now
		}
		e.mu.Lock()
		e.scheduleLocked(it, dq, againDue, time.Now())
		e.mu.Unlock()
	} else {
		e.finishItem(dq)
	}

	if sink := e.cfg.Events; sink != nil {
		for i := range w.events {
			if err := sink.Emit(ctx, w.events[i]); err != nil {
				e.metrics.EventErrors.Add(1)
			} else {
				e.metrics.EventsSent.Add(1)
			}
		}
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
