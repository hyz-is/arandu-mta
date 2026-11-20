---
name: mta-package
description: Deliver outbound email from an Arandu application or cluster with the Arandu MTA package (Go, github.com/hyz-is/arandu-mta). Use when the request is to "send email over SMTP", "write a mail queue", "retry failed deliveries", "bounce handling", "deliver to the recipient's MX", "STARTTLS", "MTA-STS", "IP warmup", "rate limit per destination domain", "throttling from Gmail or Microsoft", "suppress a recipient", "spool messages to disk", "cancel a queued email", "go get github.com/hyz-is/arandu-mta", or when the project has its own SMTP client, mail queue, retry loop, MX lookup or backoff table, or when its go.mod already requires github.com/hyz-is/arandu-mta. Covers building the Config, the interfaces to implement, the spool, the events and their order, limits, pools, shutdown, and the symptoms that mean something is wired wrong.
license: MIT
metadata:
  audience: app
---

# Using Arandu MTA

A library: the engine that takes a finished RFC 5322 message and delivers it to
the recipients' mail servers. No route, no table, no `aru migrate`; you build the
engine and call it. It does not build MIME, sign DKIM, parse bounces or serve
SMTP; those are `arandu-mail` and `arandu-smtpd`.

```bash
go get github.com/hyz-is/arandu-mta
```

## If the application already does this itself

Replace it, do not wrap it. A second retry loop is the one that sends twice.

| the application has | it becomes |
| --- | --- |
| `net/smtp` or a hand-written SMTP client | `eng.Submit` |
| a queue table and a worker that retries | `mta.Spool` (`DiskSpool`) and the engine's `Backoff` |
| a backoff table | `mta.Backoff{Schedule: ...}` |
| an MX lookup | nothing: the engine resolves, caches by TTL and handles null MX |
| a bounce classifier | `mta.Classifier`, starting from `mta.DefaultClassifier` |
| a per-domain rate limit | `Config.DomainLimits`, and adaptive back-off is already on |

## Wire it, explicitly, in `bootstrap/app.go`

```go
spool, err := mta.OpenDiskSpool(cfg.SpoolDir, mta.DiskSpoolOptions{})
eng, err := mta.New(mta.Config{
	Spool:       spool,
	EHLOName:    cfg.EHLOName,  // a name whose reverse DNS is the sending address
	Signer:      signer,        // mta.Signer; called once in Submit
	Suppression: suppression,   // mta.SuppressionChecker; asked before each attempt
	Events:      outbox,        // mta.EventSink; must enqueue durably and return
	MTASTS:      policies,      // mta.MTASTSPolicySource
	IPs:         pools,         // *mta.IPPools
	Tenant:      mta.TenantLimit{Rate: 50, Burst: 200},
})
if err := eng.Start(ctx); err != nil { ... } // recovers the spool before it returns
defer eng.Shutdown(ctx)                       // stops intake, lets running transactions finish
```

Start it once per process, after the spool directory is on a volume that
survives a restart. The engine does not close the spool: close it yourself after
`Shutdown`.

## What to know before relying on it

- `Submit` returning nil means the message is durable. Pass `Message.ID` as your
  email id; the engine refuses a second queued message with the same id
  (`ErrDuplicate`), so a retry of the API call is safe.
- Delivery is at least once. `EventSink.Emit` is called after the recipient's new
  state is written; make the sink durable (an outbox row) and idempotent on
  `Event.ID`.
- A recipient is `EventDelivered` only for a 2xx to the message. `EventDeferred`
  carries `NextAttempt`; `EventBounced` carries `Class.Type` and `Class.SubType`
  in SES names, and `Expired` when the retry window ended. `Event.Local` means
  the engine wrote the reply, not a server.
- A bounce whose `Class.Type` is `Transient` (mailbox full, message too large,
  expired) must not suppress the address; `Permanent` ones may.
- `Submit` can return `*TenantLimitError` (answer 429 with `RetryAfter`),
  `*SignError`, `ErrInvalidMessage`, `ErrInvalidAddress` (answer 400) and
  `ErrDuplicate`.
- `Cancel` stops what has not been delivered; a recipient whose transaction is
  running cannot be stopped and settles normally (`CancelResult.InFlight`).
- The tenant comes from the application's Grant when it builds the `Message`;
  the engine takes `Message.Tenant` as given and never reads it from a request.
- Render `Engine.Metrics()` with `Each`; there is no Prometheus here.
- Tests: `mtatest.Start` is an SMTP server, `mtatest.NewResolver` a table
  resolver, `mtatest.SelfSigned` a certificate. Do not write a fake SMTP
  server of your own.

## Symptoms

| symptom | cause |
| --- | --- |
| every message waits and nothing connects | `Config.Port` is 25 and the sandbox blocks it; or the domain is paused after a throttling reply (`Stats().Domains[i].PausedUntil`) |
| messages wait without events when sending from a pool | every address of the pool is at its daily quota; `QuotaExhausted` grows |
| `ErrNotStarted` | `Submit` before `Start` |
| a message is delivered twice after a crash | expected at most once per crash, between the remote 250 and the spool write |
| `corrupt/` appears in the spool directory | `DiskSpool.Load` moved an unreadable message aside; read it, do not delete it blindly |
| deferrals with `4.7.5` or `4.7.10` | an enforcing MTA-STS policy: the MX is outside it, STARTTLS is missing or the certificate does not verify |
