<p align="center">
  <img src=".github/logo.svg" alt="Arandu" width="180">
</p>

# Arandu MTA

The outbound delivery engine for the Arandu mail stack: a durable spool, a queue
per destination domain, MX resolution, an SMTP client written for the job,
retries with backoff, limits and reputation controls, and one event per
recipient.

It is a library. It registers no route, owns no table and decides no
authorization, so there is nothing to wire in `bootstrap/app.go` beyond the
engine you construct, and no `aru migrate` to run. It depends on the standard
library and `golang.org/x/net` and on nothing in this ecosystem: the MIME
builder, the DKIM signer and the bounce parser are plugged in through small
interfaces.

## Install

```bash
go get github.com/hyz-is/arandu-mta
```

```go
import mta "github.com/hyz-is/arandu-mta"
```

`arandu.mod.toml` declares `network = true` (it dials the recipients' mail
servers and asks DNS) and `filesystem = true` (the `DiskSpool`); it runs no
process and owns no table.

## Quick start

```go
spool, err := mta.OpenDiskSpool("/var/lib/mail/spool", mta.DiskSpoolOptions{})
if err != nil { return err }

eng, err := mta.New(mta.Config{
	Spool:    spool,
	EHLOName: "mx1.mail.example.com",
	Events:   outbox, // mta.EventSink
})
if err != nil { return err }
if err := eng.Start(ctx); err != nil { return err } // recovers the spool

err = eng.Submit(ctx, &mta.Message{
	ID:         "email_123",
	Tenant:     "org_1",
	MailFrom:   "bounces+123@mail.example.com",
	Recipients: []mta.Recipient{{Address: "ana@example.org"}, {Address: "bob@example.org"}},
	Data:       rfc5322, // the whole message, CRLF or LF
	Priority:   mta.PriorityTransactional,
})

// on exit: finish what is running, leave the rest in the spool
err = eng.Shutdown(ctx)
```

`Submit` returns when the message is in the spool. After that the engine owns
it. `Cancel(ctx, id)` stops what has not been delivered, `Message(id)` is a
snapshot of a queued message, `Stats()` reports the queue by domain and by
tenant, `Drain(ctx)` waits for the queue to empty, and `Shutdown(ctx)` stops
cleanly.

## What the cluster plugs in

| interface | what it answers | when the engine asks |
| --- | --- | --- |
| `Signer` | `Sign(ctx, domain, message) ([]byte, error)` | once, in `Submit`, when `Message.DKIMDomain` is set; the spool keeps the signed copy |
| `Classifier` | `Classify(code, enhanced, text) Classification` | for every non-2xx reply; `DefaultClassifier` is the minimal one |
| `SuppressionChecker` | `Suppressed(ctx, tenant, address) (bool, reason)` | before every attempt, so an address suppressed while it waited is bounced |
| `EventSink` | `Emit(ctx, Event) error` | after the new state of a recipient is written to the spool |
| `MTASTSPolicySource` | `Policy(ctx, domain) (*MTASTSPolicy, error)` | before each transaction |
| `DistributedLimiter` | `Allow(ctx, key, n) (ok, retryAfter, err)` | before each transaction, with key `domain:<name>`; an error lets the mail go |

Each has a function adapter (`SignerFunc`, `ClassifierFunc`, and so on).

## Events

One `Event` per recipient outcome, with the SMTP code, the enhanced status code,
the reply text, the exchanger that answered, the attempt number and, for a
bounce, the SES bounce type and sub type.

| `Event.Type` | name in the cluster contract | meaning |
| --- | --- | --- |
| `EventDelivered` | `DELIVERED` | a 2xx reply to the message |
| `EventDeferred` | `DELIVERY_DELAYED` | a temporary failure; `NextAttempt` says when the next try is |
| `EventBounced` | `BOUNCED` | a 5xx reply, a suppression, a null MX, an unknown domain, or the end of the retry window (`Expired`) |
| `EventFailed` | `FAILED` | an internal error: the data file is missing, or a bug |

`SENT`, `COMPLAINED` and `REJECTED` belong to the cluster, not to the engine.
`Event.Local` is true when the engine wrote the reply itself and no server said
it: a DNS failure, a connection that never opened, a null MX, a size the server
announced it would refuse. `Event.ID` is stable: `<message>/<recipient
index>/<attempt>/<TYPE>`.

`Classification` carries `Permanent` (the engine will not retry), `Type` and
`SubType` in the names SES uses (`Permanent`, `Transient`, `Undetermined`;
`General`, `NoEmail`, `Suppressed`, `MailboxFull`, `MessageTooLarge`,
`ContentRejected`, `AttachmentRejected`) and `Throttle`. A 552 mailbox-full reply
is `Permanent` for the engine, because a 5xx is never retried, and `Transient`
for the application, because it must not suppress the address.

## The spool

`Spool` is five calls: `Put`, `Update`, `ReadData`, `Delete` and `Load`.
`MemorySpool` is for tests. `DiskSpool` keeps a directory:

```
<xx>/<id>.eml     the message, written once
<xx>/<id>.meta    the metadata, replaced on every Update; a header with a CRC-32, then JSON
corrupt/          what Load could not read, moved aside
```

Every write goes to a temporary file in the same directory, is fsynced and is
renamed into place, and the directory is fsynced after. The metadata file is
what makes a message exist, and the data file is renamed first, so a crash
leaves nothing or a complete pair. `OpenDiskSpool` removes temporary files and
data files without metadata; `Load` moves a torn, mismatched or half-deleted
message to `corrupt/` and carries on. `Engine.Start` rebuilds the queue from
`Load`: a recipient that was being delivered is queued again, one already
settled is not, and a message with nothing left is deleted. A test kills a
writer with SIGKILL in the middle of a stream of `Put` calls and checks that
every acknowledged message is whole.

`DiskSpoolOptions{NoSync: true}` turns every fsync off, for tests and benchmarks.

## Scheduling and retries

One queue per destination domain, one SMTP transaction per domain per message
with every recipient as a RCPT, so a message to four people at one provider is
one connection and one transfer. Within a domain, transactional mail is taken
before marketing mail. The retry schedule is `Backoff`: 1m, 5m, 15m, 30m, 1h,
2h, 4h and then 4h again, each wait spread by 10%, until `Expiry` (72 hours),
when the recipient bounces with the last reply that was seen. A recipient
deferred for one reason is retried alone: the ones that were delivered or
bounced are not sent again.

## Resolution

MX records are tried by preference, shuffled within equal preferences. A domain
without MX records is its own exchanger if it has an address (RFC 5321 section
5.1). A null MX (RFC 7505) is a permanent failure with `556 5.1.10`, and a
domain that does not exist is `550 5.1.2`; a DNS failure is a deferral.
`CachedResolver` caches by TTL, remembers "not found" briefly, never remembers a
hiccup, and sends one lookup for any number of concurrent callers. `DNSClient`
is a resolver that carries the zone's TTL (UDP, then TCP when truncated), where
`NetResolver` over the standard library cannot see it. `Config.Resolver` takes
anything that implements `Resolver`.

## The SMTP client

Written for the engine, not wrapped: EHLO with HELO fallback; STARTTLS that is
opportunistic by default and falls back to plaintext when the handshake fails;
PIPELINING; SIZE (a message over the announced size is refused locally, without
sending DATA); 8BITMIME; SMTPUTF8 (a recipient that needs it on a server that
does not offer it is bounced `553 5.6.7`, a non-ASCII domain is converted to
A-labels when the local part is ASCII); CHUNKING with `UseChunking`, in which
`BDAT` rides in the same round trip as the envelope; one result per recipient;
connection reuse after an `RSET`, an idle pool per exchanger and source address,
and a dead pooled connection is replaced without counting an attempt. Timeouts
are those of RFC 5321 section 4.5.3.2 (`Config.Timeouts`). A connection that
fails after the message was sent and before the reply defers the recipients,
which can repeat a delivery and never loses one.

`MTASTSPolicySource` turns on MTA-STS: under `enforce` an MX outside the
policy's `mx` patterns is skipped, STARTTLS is mandatory, the certificate must
verify for the MX host name, and there is never a plaintext fallback. Under
`testing`, and with no policy, TLS is opportunistic and a certificate that does
not verify is counted in `TLSVerifyFailures`. A policy lookup that fails is
counted and does not stop the mail (RFC 8461 section 5.1).

## Limits and reputation

- Per destination domain: simultaneous connections (`MaxConnsPerDomain`,
  `DomainLimits` by exact name or `path.Match` pattern) and transactions per
  minute (`DomainLimit.MessagesPerMinute`).
- Adaptive back-off: a 421, a 451 or a 4.7.x that is not greylisting pauses the
  domain and halves its connections and its rate, doubling the pause each time
  up to `Adaptive.MaxLevel`; clean transactions bring it back
  (`Adaptive.RecoverAfter`). `Stats()` shows each domain's level and pause.
- Per tenant: `Config.Tenant` is a token bucket in recipients per second;
  `Submit` returns a `*TenantLimitError` with `RetryAfter`.
- Cluster-wide: `DistributedLimiter`.
- IP pools: `NewIPPools` with weighted selection among the addresses of a pool,
  a daily quota per address that follows a `WarmupSchedule`
  (`GeometricWarmup`, `ParseWarmupSchedule("50,100,200,500,*")`), the EHLO name
  of each address, `Usage` to read the counters and `RestoreUsage` to put them
  back after a restart. When every address of a pool is at its quota the
  message waits for the next UTC day without a delivery-delayed event and
  without spending an attempt.

## Metrics

`Engine.Metrics()` returns atomic counters. `Each(func(name, help, kind,
value))` walks them, `Snapshot()` copies them by name; the cluster renders
whatever text format it serves. There is no metrics library in this module.

## mtatest

`github.com/hyz-is/arandu-mta/mtatest` is what the tests of the engine run
against, and what the cluster's tests can run against: `Start(Config)` is an SMTP
server on a loopback port with a real DATA state machine, STARTTLS, PIPELINING,
SIZE, SMTPUTF8, CHUNKING and hooks for the reply to any stage; `NewResolver()`
answers from a table; `SelfSigned(hosts...)` makes a certificate and the pool
that trusts it. It is not linked into an application unless that application
imports it.

## Measured performance

Apple M4 Max, darwin/arm64, Go 1.26.6, `go test -bench`. The engine delivers to
an in-process fake exchanger on loopback, so the kernel's loopback path and the
fake server share the machine with the engine; the figures show what the engine
does not cost, not what a network will allow. 40,000 messages per run, three
runs, spool in memory unless said:

| scenario | messages per second | allocations per message, whole process |
| --- | --- | --- |
| 1 domain, 1 recipient, 1 KB | 69,000 to 72,000 | 70 |
| 50 domains, 1 recipient, 1 KB | 72,000 to 74,000 | 70 |
| 1 domain, 5 recipients, 1 KB | 71,000 to 73,000 | 97 |
| 50 domains, 1 recipient, 50 KB | 30,000 to 31,000 (about 1.5 GB/s) | 1,142 |
| 50 domains, 1 recipient, 1 KB, `DiskSpool` with `NoSync` | about 5,400 | 140 |
| 50 domains, 1 recipient, 1 KB, `DiskSpool` with fsync | about 100 | 144 |

The allocation column counts the fake server's too, which is most of it; the
engine's own share is about a dozen per message, found by profile. In the CPU
profile 86% of the time is in the read and write system calls.

The disk figures are the honest limit of this release: a `DiskSpool` with fsync
costs three fsyncs per `Put` and one per `Delete`, and on macOS Go's `File.Sync`
is `F_FULLFSYNC`, which takes milliseconds. The figure on a Linux server with a
power-loss-protected disk was not measured. A journal with group commit would
lift it and fits behind the same `Spool` interface.

Micro benchmarks: `ParseReplyLine` 3.9 ns, `ParseEnhancedStatus` 3.1 ns,
`ParseEHLO` 120 ns, `WriteData` 4.3 GB/s, all with no allocation; `Classify`
174 ns; `IPPools.Reserve` 177 ns.

## What is not here

DKIM signing, MIME building, DSN and ARF parsing and SPF/DMARC belong to
`arandu-mail`; the inbound SMTP server belongs to `arandu-smtpd`. DANE and TLS
reporting (RFC 8460) are not implemented. DNSSEC is not validated. Webhooks,
the API and the dashboard belong to the application.
