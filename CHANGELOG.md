# Changelog

Everything worth knowing about a release of Arandu MTA is recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A published module version is immutable: Go serves it from the proxy forever, so
a release is corrected by another release and never by moving a tag.

## [Unreleased]

### Added

- `IPPoolConfig.Location`: the time zone whose midnight starts a new warm-up day and
  whose calendar reads `WarmupStart`. The zero value is UTC, so nothing changes for
  an existing caller.

## [0.1.0] - 2026-11-20

### Added

- `Engine`: accepts messages with `Submit`, keeps them in a `Spool`, and
  delivers each recipient to the mail exchangers of its domain; `Cancel`,
  `Message`, `Stats`, `Drain` and `Shutdown`.
- `Spool`, with `MemorySpool` and `DiskSpool`: one data file and one metadata
  file per message, fsync and atomic rename, an index rebuilt on open, and the
  leftovers of a crash swept or quarantined.
- Scheduling by destination domain: one transaction per domain with every
  recipient as a RCPT, a retry schedule with jitter, transactional mail ahead
  of marketing, expiry after 72 hours by default.
- Resolution: MX with the preference order shuffled within equal preferences,
  the implicit MX of RFC 5321 section 5.1, null MX (RFC 7505) as a permanent
  failure, IPv4 and IPv6 preference, `CachedResolver` by TTL with negative
  caching and one lookup for concurrent callers, `NetResolver`, and
  `DNSClient`, a resolver that carries the TTL of the zone.
- An SMTP client written for the engine: EHLO with HELO fallback, opportunistic
  STARTTLS that falls back to plaintext when the handshake fails, PIPELINING,
  SIZE, 8BITMIME, SMTPUTF8, CHUNKING with BDAT in the same round trip as the
  envelope, a result per recipient, connection reuse with RSET, an idle pool
  per exchanger, the timeouts of RFC 5321 section 4.5.3.2, source address bind
  and an EHLO name per address.
- MTA-STS enforcement through `MTASTSPolicySource`: policy `mx` matching,
  mandatory STARTTLS and certificate verification under `enforce`.
- Limits: connections and messages per minute per destination domain with
  pattern overrides, adaptive back-off on 421, 451 and 4.7.x, a token bucket per
  tenant, `DistributedLimiter` for cluster-wide limits.
- `IPPools`: weighted selection among source addresses, daily warm-up quotas,
  `WarmupSchedule`, usage readout and restore.
- `Signer`, `Classifier` with `DefaultClassifier`, `SuppressionChecker`,
  `EventSink` and `MTASTSPolicySource`: the interfaces the cluster wires.
- `Event` per recipient: delivered, deferred, bounced and failed, with the SMTP
  code, the enhanced code, the text, the exchanger and the SES bounce type.
- `Metrics`: atomic counters walked by `Each`, with no metrics library.
- `mtatest`: an in-process SMTP server, a table resolver and a self-signed
  certificate.
