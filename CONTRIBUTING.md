# Contributing

Thank you for considering a contribution.

## Before you open a pull request

Run the four gates. They are what CI runs, and a pull request that fails one of
them fails for everybody who pulls after it.

```bash
export GOWORK=off
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*' -not -name '*.kyse.go')
go build ./...
go vet ./...
go test -race ./...
```

The two filters on `gofmt` are not preference. `gofmt` is the only tool in the
chain that ignores build tags, so it reads files the compiler deliberately
excludes; `testdata/` holds fixtures that are invalid on purpose.

A change to a parser gets a fuzz run too, of the target that covers it:

```bash
go test -run='^$' -fuzz='^FuzzParseReplyLine$' -fuzztime=30s ./tests/Unit
```

A change to the delivery path gets a benchmark run, and the numbers go in the
pull request:

```bash
go test -run='^$' -bench='BenchmarkEngineThroughput/memory' -benchtime=40000x ./tests/Unit
```

## What a change has to keep true

1. **A recipient is settled once.** Delivered, bounced, failed or cancelled are
   final; no code path moves a recipient out of them, and no path sends to a
   recipient whose state is not queued or deferred.
2. **State is persisted before it is announced.** `settle` writes the spool and
   only then calls the `EventSink`. A crash may lose an event; it must not send
   a message twice for that reason alone.
3. **A refusal from a server is never read as a success, and a success is never
   invented.** A recipient is `Delivered` only for a 2xx reply to the message.
   There is no test double that answers for a server in production code.
4. **The hot path does not allocate what it can reuse.** `transact`, the reply
   parser and `WriteData` allocate nothing that a pooled buffer could hold. A
   change that adds an allocation per message shows its benchmark.
5. **This stays a library.** No `init`, no global registry, no framework import,
   and nothing beyond the standard library and `golang.org/x/*`.
   `TestTheModuleIsALibrary` and `TestTheModuleNeedsNothingButTheStandardLibraryAndX`
   hold it.
6. **`arandu.mod.toml` matches the code.** Adding an outbound call, a file
   access or a process means declaring it there in the same commit.

## Style

Everything in the source is in English: identifiers, doc comments, internal
comments, error messages, and the names and messages of tests. `pkg.go.dev`
publishes the doc comments, and its readers are users of this package.

Every exported symbol carries a doc comment saying what it does. The comment
documents the symbol and nothing else: no dates, no issue numbers, no
references to other repositories.

## Commits

One commit per logical change. Formatting is not mixed with behaviour, because
a diff that does both is a diff nobody reviews.

## Reporting a vulnerability

Do not open an issue. See [SECURITY.md](SECURITY.md).

## Licence

By contributing you agree that your contribution is licensed under the MIT
licence, the same as the rest of github.com/hyz-is/arandu-mta.
