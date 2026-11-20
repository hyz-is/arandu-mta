---
name: mta-release
description: Get this Arandu package green, measured and published. Use when the request is to "run the gates", "check it builds", "the tests fail", "run the fuzzers", "run the benchmarks", "what is the throughput", "go build says the directory prefix does not contain modules listed in go.work", "update arandu.mod.toml", "add a dependency", "tag a release", "publish it", "go get cannot find the module", "write the changelog", or before opening a pull request. Covers the four gates, the fuzz runs, the benchmark run and why a polluted run fails, what the manifest declares and who checks it, why the module requires golang.org/x and nothing else, and the immutability of a published module version.
license: MIT
---

# Getting it green and out

## The four gates

Nothing is finished until all four exit zero.

```sh
export GOWORK=off
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*' -not -name '*.kyse.go')
go build ./...
go vet ./...
go test -race ./...
```

`GOWORK=off` first. This checkout may sit beside a Go workspace that does not
list it, and then `go build ./...` exits 1 before compiling anything with
`directory prefix . does not contain modules listed in go.work`. With the
workspace off the module resolves the versions in `go.mod`, which is what CI
compiles against and what somebody's `go get` will get.

`aru doctor` is not a gate: it reads applications, and this is a library.

## The fuzz runs

`go test` runs the seeds of every fuzz target each time. Before a release, and
after any change to a parser, run each for a while; `go test -fuzz` takes one
target at a time:

```sh
for f in FuzzParseReplyLine FuzzParseEnhancedStatus FuzzParseEHLO FuzzDecodeMeta \
         FuzzParseWarmupSchedule FuzzWriteData FuzzClassify FuzzMatchesMX \
         FuzzAddress FuzzParsePriority FuzzResolvConf FuzzDNSClientAgainstGarbage \
         FuzzClientAgainstAServerThatSaysAnything; do
  go test -run='^$' -fuzz="^$f\$" -fuzztime=30s ./tests/Unit
done
```

A failure writes its input under `tests/Unit/testdata/fuzz/`. Commit that file
with the fix: it becomes a seed that runs on every `go test`.

## The benchmarks

```sh
go test -run='^$' -bench='BenchmarkEngineThroughput/memory' -benchtime=40000x -count=3 ./tests/Unit
go test -run='^$' -bench='Benchmark(Parse|WriteData|Classify|IPPool|Tenant|Meta|Backoff)' ./tests/Unit
```

The throughput benchmark fails, on purpose, when the run deferred a message or
failed a connection: that run measured the retry schedule, not the engine. On
macOS it happens when a long series of runs exhausts the ephemeral loopback
ports. Rerun after a minute; do not raise the numbers by hiding the failure.
`disk-fsync` is slow by nature (a full fsync per write); give it
`-benchtime=1500x`. A change to the delivery path states the before and after in
the pull request.

## What the manifest declares, and who reads it

`arandu.mod.toml` is a promise, and the check that gives it weight runs here:
`TestTheManifestIsWhatTheCodeDoes` compares the four permissions with what the
code calls, by AST. `network` and `filesystem` are true, `exec` and
`migrations` are false. A call to another program or a table makes a different
package, not a change to this one.

## Adding a dependency

Do not, beyond `golang.org/x/*`. This module goes into other people's builds.
`TestTheModuleNeedsNothingButTheStandardLibraryAndX` refuses any other import
and any other `require`, and `go.mod` carries no `replace`.

## Publishing

A published Go module version is immutable; a mistake is corrected by another
release, never by moving a tag. Before tagging: the four gates pass with
`GOWORK=off`; each fuzz target has run; `CHANGELOG.md` has the entry under the
version and `UPGRADE.md` a `## vX.Y.Z` heading for it; the benchmark figures in
`README.md` are the ones just measured.

Publishing is the owner's decision. The repository is created in the `hyz-is`
organization from `arandu-io/package-skeleton`, the local history is rebased onto
its first commit, and only then is a tag pushed.

Changes that break an installer without touching a signature, and so need a line
in the changelog and in `UPGRADE.md`: the retry schedule, the default limits, the
event `ID` format, the spool file format (a new reader must read the old files),
and what `DefaultClassifier` calls permanent.
