package mta

import "sync/atomic"

// MetricKind says how a metric behaves, so a renderer can write the right
// "# TYPE" line.
type MetricKind uint8

const (
	// KindCounter only grows.
	KindCounter MetricKind = iota
	// KindGauge goes up and down.
	KindGauge
)

// String returns "counter" or "gauge".
func (k MetricKind) String() string {
	if k == KindGauge {
		return "gauge"
	}
	return "counter"
}

// Metrics are the engine's counters, plain atomics. There is no Prometheus
// dependency: Each walks them with a name, a help line, a kind and a value, and
// the cluster renders whatever text format it serves.
type Metrics struct {
	// Intake.
	MessagesSubmitted   atomic.Uint64
	RecipientsSubmitted atomic.Uint64
	SubmitRejected      atomic.Uint64
	TenantLimited       atomic.Uint64
	BytesSubmitted      atomic.Uint64

	// Outcomes, one per recipient.
	Delivered  atomic.Uint64
	Deferred   atomic.Uint64
	Bounced    atomic.Uint64
	Failed     atomic.Uint64
	Suppressed atomic.Uint64
	Expired    atomic.Uint64
	Cancelled  atomic.Uint64

	// Transactions and traffic.
	Transactions   atomic.Uint64
	BytesSent      atomic.Uint64
	Throttled      atomic.Uint64
	LimiterDenied  atomic.Uint64
	LimiterErrors  atomic.Uint64
	QuotaExhausted atomic.Uint64
	NullMX         atomic.Uint64

	// Connections.
	ConnectionsOpened atomic.Uint64
	ConnectionsReused atomic.Uint64
	ConnectionsFailed atomic.Uint64
	ConnectionsStale  atomic.Uint64
	TLSHandshakes     atomic.Uint64
	TLSFallbacks      atomic.Uint64
	TLSVerifyFailures atomic.Uint64
	MTASTSEnforced    atomic.Uint64
	MTASTSErrors      atomic.Uint64
	MTASTSRejectedMX  atomic.Uint64

	// DNS.
	DNSLookups   atomic.Uint64
	DNSCacheHits atomic.Uint64
	DNSErrors    atomic.Uint64

	// Spool and events.
	SpoolErrors atomic.Uint64
	EventsSent  atomic.Uint64
	EventErrors atomic.Uint64

	// Gauges.
	PendingRecipients atomic.Int64
	ActiveWorkers     atomic.Int64
	IdleConnections   atomic.Int64
	QueuedMessages    atomic.Int64
}

// MetricsSnapshot is a copy of every metric at one moment, by name.
type MetricsSnapshot map[string]uint64

// Each calls fn for every metric. Gauges are reported as their current value,
// clamped at zero.
func (m *Metrics) Each(fn func(name, help string, kind MetricKind, value uint64)) {
	c := func(name, help string, v *atomic.Uint64) { fn("mta_"+name, help, KindCounter, v.Load()) }
	g := func(name, help string, v *atomic.Int64) {
		n := v.Load()
		if n < 0 {
			n = 0
		}
		fn("mta_"+name, help, KindGauge, uint64(n))
	}
	c("messages_submitted_total", "Messages accepted into the spool.", &m.MessagesSubmitted)
	c("recipients_submitted_total", "Recipients accepted into the spool.", &m.RecipientsSubmitted)
	c("submit_rejected_total", "Messages refused by Submit.", &m.SubmitRejected)
	c("tenant_limited_total", "Messages refused by the tenant rate limit.", &m.TenantLimited)
	c("bytes_submitted_total", "Bytes of message data accepted.", &m.BytesSubmitted)
	c("delivered_total", "Recipients the remote server accepted with 2xx.", &m.Delivered)
	c("deferred_total", "Recipient attempts that ended in a temporary failure.", &m.Deferred)
	c("bounced_total", "Recipients that will never be delivered.", &m.Bounced)
	c("failed_total", "Recipients ended by an internal error.", &m.Failed)
	c("suppressed_total", "Recipients bounced by the suppression check.", &m.Suppressed)
	c("expired_total", "Recipients bounced because the retry window ended.", &m.Expired)
	c("cancelled_total", "Recipients cancelled before delivery.", &m.Cancelled)
	c("transactions_total", "SMTP transactions started.", &m.Transactions)
	c("bytes_sent_total", "Bytes of message data written to remote servers.", &m.BytesSent)
	c("throttled_total", "Replies that asked the sender to slow down.", &m.Throttled)
	c("limiter_denied_total", "Sends delayed by the distributed limiter.", &m.LimiterDenied)
	c("limiter_errors_total", "Distributed limiter calls that failed open.", &m.LimiterErrors)
	c("ip_quota_exhausted_total", "Sends delayed because every source IP was at its daily quota.", &m.QuotaExhausted)
	c("null_mx_total", "Domains refused for publishing a null MX.", &m.NullMX)
	c("connections_opened_total", "SMTP connections opened.", &m.ConnectionsOpened)
	c("connections_reused_total", "Transactions that reused an idle connection.", &m.ConnectionsReused)
	c("connections_failed_total", "Connections that failed before a transaction.", &m.ConnectionsFailed)
	c("connections_stale_total", "Idle connections found dead on reuse.", &m.ConnectionsStale)
	c("tls_handshakes_total", "STARTTLS handshakes completed.", &m.TLSHandshakes)
	c("tls_fallbacks_total", "Opportunistic handshakes that failed and fell back to plaintext.", &m.TLSFallbacks)
	c("tls_verify_failures_total", "Certificates that did not verify, accepted or refused.", &m.TLSVerifyFailures)
	c("mtasts_enforced_total", "Transactions run under an enforcing MTA-STS policy.", &m.MTASTSEnforced)
	c("mtasts_errors_total", "MTA-STS policy lookups that failed.", &m.MTASTSErrors)
	c("mtasts_rejected_mx_total", "MX hosts skipped because the MTA-STS policy forbids them.", &m.MTASTSRejectedMX)
	c("dns_lookups_total", "Lookups sent to the resolver.", &m.DNSLookups)
	c("dns_cache_hits_total", "Lookups answered from the cache.", &m.DNSCacheHits)
	c("dns_errors_total", "Lookups that failed.", &m.DNSErrors)
	c("spool_errors_total", "Spool operations that failed.", &m.SpoolErrors)
	c("events_sent_total", "Events handed to the sink.", &m.EventsSent)
	c("event_errors_total", "Events the sink refused.", &m.EventErrors)
	g("pending_recipients", "Recipients that still wait for a final outcome.", &m.PendingRecipients)
	g("active_workers", "Delivery workers running a transaction.", &m.ActiveWorkers)
	g("idle_connections", "Connections waiting in the idle pool.", &m.IdleConnections)
	g("queued_messages", "Messages in the queue.", &m.QueuedMessages)
}

// Snapshot returns every metric by name.
func (m *Metrics) Snapshot() MetricsSnapshot {
	s := make(MetricsSnapshot, 48)
	m.Each(func(name, _ string, _ MetricKind, v uint64) { s[name] = v })
	return s
}
