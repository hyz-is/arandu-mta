# Skills

Procedures an assistant follows when working on this package.

They live in `.agents/skills/<name>/SKILL.md`, which is the path the coding
assistants read from. It is one directory rather than a file per vendor, so a
skill written once is read by whatever this package is being written with.

Each file opens with frontmatter carrying a `name` and a `description`. The
`name` has to equal the directory name exactly, or the skill is not loaded. The
description is what a tool reads to decide whether the skill is relevant, so it
names the situation you are in rather than the topic it covers.

| skill | when it fires |
| --- | --- |
| `mta-release` | the gates, the fuzz runs, the benchmarks, the manifest, a dependency, a version, a tag |
| `mta-vault-notes` | writing the note, the gap or the journal entry, when this checkout sits inside the Arandu Obsidian vault |
| `mta-package` | wiring or operating the delivery engine **in an application**: `Config`, the hooks, the spool, events, limits, IP pools |

`mta-package` has a different audience from the other two, and that is on
purpose: it travels with the package so that an assistant working in somebody
else's project, the one running `go get`, has the wiring, the event contract and
the failure modes in front of it instead of writing a queue and an SMTP client
of its own. Its frontmatter says so, under `metadata`, with `audience: app`;
that line is what `aru skills:sync` reads, and no other skill here carries it.

`mta-vault-notes` fires on a condition rather than on a task: it applies only
when `MOC-arandu.md`, `plans/cmd/audit-vault/` and `45-modules/` are actually
beside this checkout. Outside the vault it is inert.

## Why these exist

The common failure modes when changing this package are a recipient moved out
of a terminal state, an event emitted before the state it reports is written,
an allocation added to the per-message path, a `time.Sleep` in a worker that
should have been a timer entry, a server reply parsed by splitting a string, a
`Spool` that reports a message durable before the rename, and a fake that answers
for a server in production code. None belongs here.

The package is built to be checked rather than trusted: an in-process SMTP
server with hooks for every stage, a process killed with SIGKILL in the middle of
writing the spool, a fuzz target for every parser and for the client against a
server that says anything, and benchmarks that fail when a run measured the
retry schedule instead of the engine.

## Adding your own

A skill in this directory is yours and travels with the repository. Keep it a
procedure rather than a description: a file that says "read the documentation"
never changes what anybody does.
