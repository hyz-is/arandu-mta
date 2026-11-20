# Working on Arandu MTA

This is an Arandu package: the outbound delivery engine of the mail stack. It
accepts messages, keeps them in a durable spool, resolves the recipients'
domains, and delivers over SMTP with retries, limits and one event per
recipient. It is a Go module somebody `go get`s and imports.

It began as the package skeleton, configured as `hyz-is/mta`, and the HTTP
module the template ships was removed on purpose: there is no entity, no table,
no migration, no policy, no route, no view and no `Module` to register. What a
skeleton package wires in `bootstrap/app.go`, this one does not need, and
nothing here should grow back into it. Read `.agents/skills/` before writing
code; each skill is a procedure, and the one you need is named by the situation
you are in.

## The gates

Nothing is finished until all four exit zero.

```sh
export GOWORK=off
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*' -not -name '*.kyse.go')
go build ./...
go vet ./...
go test -race ./...
```

`GOWORK=off` is not a preference: beside a workspace that does not list this
module, every command fails before it compiles anything. Before a release, give
each parser a short fuzz run; the targets are listed in the `mta-release` skill.
`aru doctor` is not a gate; it reads applications.

## What this repository holds

```
doc.go                    the package comment and the guarantees
message.go                Message, Recipient, states, priorities, address checks
interfaces.go             Signer, Classifier, SuppressionChecker, EventSink,
                          MTASTSPolicySource, DistributedLimiter, MTASTSPolicy
classify.go               Classification and the default classifier
events.go                 Event and its types
config.go                 Config, DomainLimit, AdaptiveConfig
engine.go                 Engine: Submit, Start, Cancel, Stats, Drain, Shutdown,
                          the timers and the run queue
queue.go                  items, per-domain queues, the timer heap
deliver.go                the worker: claim, check, deliver, settle
connect.go, pool.go       dial, banner, EHLO, STARTTLS, the idle pool
client.go, transact.go    SMTP session pieces and the transaction itself
reply.go                  reply parsing, enhanced codes, EHLO capabilities
resolver.go, dns.go       Resolver, CachedResolver, NetResolver, DNSClient
bucket.go, backoff.go     token bucket, tenant limiter, retry schedule
ippool.go                 IP pools and warm-up
spool.go, diskspool.go    Spool, MemorySpool, DiskSpool, the metadata format
metrics.go                the atomic counters
mtatest/                  the in-process SMTP server, resolver and certificate
tests/Unit/               every test, fuzz target and benchmark (package unit_test)
```

## What does not exist here, on purpose

| A model reaches for | What is here instead |
| --- | --- |
| a dependency on `arandu-mail` for MIME, DKIM or DSN | the `Signer` interface; the cluster wires the implementation |
| a metrics library, a logger, a global registry | `Metrics` with `Each`; errors are returned or counted |
| `net/smtp` | `client.go` and `transact.go`: per-recipient results, pipelining and BDAT are not in it |
| `sleep` in a worker to wait for a retry | `scheduleLocked` and the timer heap |
| a goroutine per message or per domain | a fixed pool of workers and a run queue of domains |
| `init`, a package-level `Default`, a singleton engine | `New(Config)`; `TestTheModuleIsALibrary` refuses an `init` |
| a table or a model for the queue | the spool directory |
| a fake that returns delivered | nothing; `mtatest` is a server, and it is not imported by production code |
| an import beyond the standard library and `golang.org/x/*` | `TestTheModuleNeedsNothingButTheStandardLibraryAndX` |

## The properties

A change that breaks one of them is not merged, whatever else it improves.

1. **A recipient is settled once.** Delivered, bounced, failed and cancelled are
   final. A recipient is only claimed in state queued or deferred, and `settle`
   is the only function that moves it.
2. **State before event.** `settle` persists the spool, then calls the
   `EventSink`. The reverse order can send a message twice.
3. **Delivered means 250.** `EventDelivered` is produced only from a 2xx reply
   to the message. A local failure never produces it.
4. **The retry window ends in a bounce, not in silence.** A deferral whose next
   attempt falls after `ExpiresAt` becomes a bounce with `Expired`.
5. **A throttled domain slows down.** A reply the classifier marks `Throttle`
   lowers the domain's connections and rate and pauses it; clean transactions
   restore them.
6. **Policy beats opportunism.** Under an enforcing MTA-STS policy there is no
   plaintext fallback and no unverified certificate.
7. **The hot path reuses.** The reply parser, `WriteData` and `transact`
   allocate nothing that a pooled buffer holds, and a connection is reused
   after an `RSET`.
8. **`arandu.mod.toml` matches the code**, compared by
   `TestTheManifestIsWhatTheCodeDoes`.

## Writing code

Everything in the source is in English: identifiers, doc comments, internal
comments, error messages, and the names and messages of tests. Every exported
symbol carries a doc comment, and the comment documents the symbol and nothing
else: no dates, no issue numbers, no name of another repository.

Tests go under `tests/Unit`, declaring `package unit_test`, and import the
package by its module path, which is what makes them see exactly what a caller
sees. A new behaviour is tested against `mtatest`, a new parser gets a fuzz
target next to its unit test, and a change to the delivery path gets a
benchmark and a profile.

Commits are `HYZIS <admin@hyz.is>`, set in the repository's local git config,
with no attribution of any kind in the message.
