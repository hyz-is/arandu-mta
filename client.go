package mta

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/idna"
)

// Timeouts are the time limits of an SMTP session. The defaults are the ones
// RFC 5321 section 4.5.3.2 recommends, with a short connect timeout.
type Timeouts struct {
	// Connect bounds the TCP handshake. Default 30s.
	Connect time.Duration
	// Greeting bounds the wait for the 220 banner. Default 5m.
	Greeting time.Duration
	// Command bounds the wait for the reply to MAIL, RCPT, RSET, EHLO and
	// STARTTLS. Default 5m.
	Command time.Duration
	// DataInit bounds the wait for the 354 after DATA. Default 2m.
	DataInit time.Duration
	// DataBlock bounds each 64 KiB written during DATA. Default 3m.
	DataBlock time.Duration
	// DataTermination bounds the wait for the reply after the message. Default
	// 10m.
	DataTermination time.Duration
}

func (t Timeouts) withDefaults() Timeouts {
	def := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&t.Connect, 30*time.Second)
	def(&t.Greeting, 5*time.Minute)
	def(&t.Command, 5*time.Minute)
	def(&t.DataInit, 2*time.Minute)
	def(&t.DataBlock, 3*time.Minute)
	def(&t.DataTermination, 10*time.Minute)
	return t
}

// DialTarget is what the engine asks Config.Dial to connect to.
type DialTarget struct {
	// Host is the exchanger's name, for logs and for tests that map names to
	// listeners.
	Host string
	// Addr and Port are where to connect.
	Addr netip.Addr
	Port int
	// Local is the source address to bind; invalid means any.
	Local netip.Addr
	// Timeout is the connect timeout.
	Timeout time.Duration
}

func defaultDial(ctx context.Context, t DialTarget) (net.Conn, error) {
	d := net.Dialer{Timeout: t.Timeout}
	if t.Local.IsValid() {
		d.LocalAddr = &net.TCPAddr{IP: t.Local.AsSlice()}
	}
	return d.DialContext(ctx, "tcp", netip.AddrPortFrom(t.Addr, uint16(t.Port)).String())
}

// clientOpts is what a connection needs from the engine's configuration.
type clientOpts struct {
	timeouts     Timeouts
	port         int
	dial         func(context.Context, DialTarget) (net.Conn, error)
	rootCAs      *x509.CertPool
	sessions     tls.ClientSessionCache
	noSTARTTLS   bool
	chunking     bool
	noPipelining bool
	maxUses      int
	metrics      *Metrics
}

// smtpConn is one SMTP connection and what is known about its server.
type smtpConn struct {
	nc   net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer
	host string
	addr netip.Addr
	key  poolKey

	tls      bool
	verified bool
	caps     Capabilities
	ehlo     string

	uses      int
	idleSince time.Time
	broken    bool

	text []byte // reply text of the last readReply, lines joined by '\n'
	idx  []int
	wire []string
	run  txRun
}

type poolKey struct {
	host   string
	addr   netip.Addr
	local  netip.Addr
	strict bool
}

const (
	maxReplyText = 8 << 10
	readBufSize  = 4 << 10
	writeBufSize = 16 << 10
)

var (
	errProtocol = errors.New("smtp protocol error")
)

func (c *smtpConn) setDeadline(d time.Duration) {
	_ = c.nc.SetDeadline(time.Now().Add(d))
}

func (c *smtpConn) close() {
	c.broken = true
	_ = c.nc.Close()
}

// readReply reads a whole reply. The text stays in c.text until the next call.
func (c *smtpConn) readReply() (int, []byte, error) {
	c.text = c.text[:0]
	code := 0
	for n := 0; ; n++ {
		line, err := c.br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// An overlong line: keep its head and drop the rest.
			head := append([]byte(nil), line...)
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = c.br.ReadSlice('\n')
			}
			if err != nil {
				return 0, nil, err
			}
			line = append(head, '\r', '\n')
		} else if err != nil {
			return 0, nil, err
		}
		lcode, last, text, perr := ParseReplyLine(line)
		if perr != nil {
			return 0, nil, fmt.Errorf("%w: %q", errProtocol, trimForError(line))
		}
		if n == 0 {
			code = lcode
		} else if lcode != code {
			return 0, nil, fmt.Errorf("%w: reply code changed from %d to %d", errProtocol, code, lcode)
		}
		if len(c.text) < maxReplyText {
			if n > 0 {
				c.text = append(c.text, '\n')
			}
			c.text = append(c.text, text...)
		}
		if last {
			return code, c.text, nil
		}
		if n > 200 {
			return 0, nil, fmt.Errorf("%w: reply has too many lines", errProtocol)
		}
	}
}

func trimForError(b []byte) []byte {
	b = bytes.TrimRight(b, "\r\n")
	if len(b) > 80 {
		b = b[:80]
	}
	return b
}

// command writes one command line and flushes it.
func (c *smtpConn) command(parts ...string) error {
	for _, p := range parts {
		if _, err := c.bw.WriteString(p); err != nil {
			return err
		}
	}
	if _, err := c.bw.WriteString("\r\n"); err != nil {
		return err
	}
	return c.bw.Flush()
}

func (c *smtpConn) greeting(o *clientOpts) (Reply, error) {
	c.setDeadline(o.timeouts.Greeting)
	code, text, err := c.readReply()
	if err != nil {
		return Reply{}, err
	}
	if code != 220 {
		return buildReply(code, text), nil
	}
	return Reply{Code: 220}, nil
}

// hello sends EHLO, falling back to HELO when the server does not know EHLO.
func (c *smtpConn) hello(o *clientOpts) (Reply, error) {
	c.setDeadline(o.timeouts.Command)
	if err := c.command("EHLO ", c.ehlo); err != nil {
		return Reply{}, err
	}
	code, text, err := c.readReply()
	if err != nil {
		return Reply{}, err
	}
	if code/100 == 2 {
		c.caps = ParseEHLO(string(text))
		return Reply{Code: code}, nil
	}
	if code == 421 || code/100 == 4 {
		return buildReply(code, text), nil
	}
	// 500, 501, 502, 503, 504 and the rest: the server does not speak EHLO.
	if err := c.command("HELO ", c.ehlo); err != nil {
		return Reply{}, err
	}
	code, text, err = c.readReply()
	if err != nil {
		return Reply{}, err
	}
	if code/100 != 2 {
		return buildReply(code, text), nil
	}
	c.caps = Capabilities{}
	return Reply{Code: code}, nil
}

func (c *smtpConn) quit() {
	if c.broken {
		_ = c.nc.Close()
		return
	}
	_ = c.nc.SetDeadline(time.Now().Add(2 * time.Second))
	_ = c.command("QUIT")
	_ = c.nc.Close()
	c.broken = true
}

// WriteData writes a message as the DATA command's payload: every line ends
// in CRLF whatever it ended in before, a line that starts with a dot gets a
// second one, and the terminating ".CRLF" follows.
func WriteData(w *bufio.Writer, data []byte) error {
	for len(data) > 0 {
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}
		if len(line) > 0 && line[0] == '.' {
			if err := w.WriteByte('.'); err != nil {
				return err
			}
		}
		if _, err := w.Write(line); err != nil {
			return err
		}
		if _, err := w.WriteString("\r\n"); err != nil {
			return err
		}
	}
	_, err := w.WriteString(".\r\n")
	return err
}

func has8Bit(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return true
		}
	}
	return false
}

// asciiAddress converts the domain of an address to its A-label form for a
// server without SMTPUTF8. A non-ASCII local part cannot be converted.
func asciiAddress(addr string) (string, bool) {
	at := -1
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == '@' {
			at = i
			break
		}
	}
	if at < 0 || hasNonASCII(addr[:at]) {
		return "", false
	}
	d, err := idna.Lookup.ToASCII(addr[at+1:])
	if err != nil {
		return "", false
	}
	return addr[:at+1] + d, true
}

type txStatus uint8

const (
	// txDone: every reply is final.
	txDone txStatus = iota
	// txStale: a reused connection was dead; dial a fresh one to the same host.
	txStale
	// txFail: the server could not take the transaction at all; try another.
	txFail
)

type cmdKind uint8

const (
	kRSET cmdKind = iota
	kMAIL
	kRCPT
	kDATA
	kBDAT
)

// failAll gives every recipient the same reply.
func (c *smtpConn) failAll(replies []Reply, r Reply, force bool) (txStatus, Reply, error) {
	for _, ri := range c.idx {
		if force || replies[ri].Code == 0 {
			replies[ri] = r
		}
	}
	c.uses++
	return txDone, Reply{}, nil
}

// failRest gives every recipient without a verdict the reply and closes.
func (c *smtpConn) failRest(replies []Reply, r Reply) (txStatus, Reply, error) {
	c.broken = true
	return c.failAll(replies, r, false)
}

// dataLost is a connection that failed while the message was in flight, or
// before its final reply: the server may or may not have accepted it, so the
// recipients are deferred, which can repeat a delivery and never loses one.
func (c *smtpConn) dataLost(replies []Reply, err error) (txStatus, Reply, error) {
	c.broken = true
	r := localReply(451, "4.4.2", "connection lost before "+c.host+" confirmed the message: "+err.Error())
	for _, ri := range c.idx {
		if replies[ri].Code == 0 {
			replies[ri] = r
		}
	}
	return txDone, Reply{}, nil
}

func (c *smtpConn) finishFail(st txStatus, why Reply, err error, reuse bool) (txStatus, Reply, error) {
	c.broken = true
	if st == txFail && err != nil && reuse && c.uses > 0 && why.Code == 0 {
		// An I/O error on a connection that already served a transaction is, far
		// more often than not, the server having closed an idle connection.
		return txStale, why, err
	}
	return st, why, err
}

func deadlineAfter(d time.Duration) time.Time { return time.Now().Add(d) }
