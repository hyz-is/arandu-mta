# Security policy

## Supported versions

The latest minor release of Arandu MTA receives security fixes. Older minor
releases do not: a published Go module version is immutable, so a fix is a new
release rather than a moved tag.

## Reporting a vulnerability

Report it privately, through GitHub's advisory form:

<https://github.com/hyz-is/arandu-mta/security/advisories/new>

Do not open a public issue and do not describe the problem in a pull request.
A report that arrives in public is a report every reader of this repository can
act on before there is a release to upgrade to.

Include what you need to reproduce it: the version, the configuration, and the
server behaviour or the input that triggers it. Never real mailboxes or message
contents: the test server in `mtatest` reproduces any wire behaviour.

Expect an acknowledgement within a few days. If the report is confirmed, the
fix, the release and the advisory are published together, and you are credited
unless you ask not to be.

## What is in scope

- A command injection into an SMTP session: any envelope address, sender or
  message content that makes the client write a command the caller did not
  ask for.
- A recipient delivered after it was cancelled, suppressed or settled, or a
  message sent to a recipient outside its envelope.
- A message delivered in plaintext although an enforcing MTA-STS policy was in
  force, or to a host the policy does not allow, or over a certificate that did
  not verify.
- A server reply, DNS answer or spool file that makes the engine panic, hang or
  allocate without bound.
- A spool file that can be made to read or write outside the spool directory.

## What is not

- A remote server that accepts mail it should refuse, or refuses mail it should
  accept. The engine records what the server said.
- Reputation: whether a provider trusts a source address.
- A vulnerability in `golang.org/x/*` or in the Go standard library. Report
  those to the Go project.
