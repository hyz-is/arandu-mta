// Package mtatest holds the test doubles of the outbound engine: an SMTP server
// that runs in the test process and records what it receives, a resolver that
// answers from a table, and a self-signed certificate for STARTTLS.
//
// The server speaks enough ESMTP to exercise a client honestly: EHLO and HELO,
// STARTTLS, PIPELINING, SIZE, 8BITMIME, SMTPUTF8, CHUNKING and BDAT, RSET, NOOP
// and QUIT, a real DATA state machine with dot unstuffing, and hooks that let a
// test decide the reply to any stage. It keeps no mailbox and sends nothing.
package mtatest
