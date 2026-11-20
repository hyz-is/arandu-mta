package mtatest

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Reply is a reply a hook gives the server to send.
type Reply struct {
	Code     int
	Enhanced string
	Text     string
}

// Received is a message the server accepted.
type Received struct {
	Seq      int
	Conn     int
	Helo     string
	From     string
	Rcpts    []string
	Data     []byte
	TLS      bool
	At       time.Time
	Remote   string
	BodyType string
	UTF8     bool
}

// Config configures a Server. The zero value is a plain server on a loopback
// port that offers PIPELINING, 8BITMIME and ENHANCEDSTATUSCODES.
type Config struct {
	// Hostname is announced in the banner and the EHLO reply.
	Hostname string
	// TLS, when set, makes the server offer STARTTLS.
	TLS *tls.Config
	// RequireTLS refuses MAIL on a plaintext connection with 530.
	RequireTLS bool
	// NoPipelining, NoEnhanced and NoEHLO remove those features: NoEHLO makes the
	// server answer EHLO with 502, as an old server does.
	NoPipelining, NoEnhanced, NoEHLO bool
	// Size is announced in SIZE and enforced; 0 announces and enforces nothing.
	Size int64
	// SMTPUTF8 and Chunking are offered when true.
	SMTPUTF8, Chunking bool
	// Discard keeps counts but not the messages; for benchmarks.
	Discard bool
	// IdleTimeout closes a connection that sends nothing; default 30s.
	IdleTimeout time.Duration

	// Greeting may replace the banner; a reply with a 4xx or 5xx code is sent and
	// the connection closed. conn counts connections from 1.
	Greeting func(conn int) *Reply
	// OnMail, OnRcpt and OnData decide the reply to MAIL FROM, each RCPT TO and
	// the end of the message. A nil return means success. OnData receives the
	// message; the reply applies to all of its recipients.
	OnMail func(from string) *Reply
	OnRcpt func(rcpt string) *Reply
	OnData func(m *Received) *Reply
}

// Stats counts what the server saw.
type Stats struct {
	Connections int64
	Messages    int64
	Rsets       int64
	StartTLS    int64
	Commands    int64
	Rejected    int64
}

// Server is a running fake SMTP server.
type Server struct {
	cfg  Config
	ln   net.Listener
	wg   sync.WaitGroup
	done atomic.Bool

	conns, msgs, rsets, starttls, cmds, rejected atomic.Int64

	mu       sync.Mutex
	received []Received
	active   map[net.Conn]struct{}
	notify   chan struct{}
}

// Start listens on 127.0.0.1 and serves until Close.
func Start(cfg Config) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	if cfg.Hostname == "" {
		cfg.Hostname = "mx.test"
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 30 * time.Second
	}
	s := &Server{cfg: cfg, ln: ln, active: make(map[net.Conn]struct{}), notify: make(chan struct{}, 1)}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

// Addr returns the listening address, "127.0.0.1:port".
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Port returns the listening port.
func (s *Server) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// Close stops the server and drops its connections.
func (s *Server) Close() error {
	if !s.done.CompareAndSwap(false, true) {
		return nil
	}
	err := s.ln.Close()
	s.mu.Lock()
	for c := range s.active {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

// Stats returns the counters.
func (s *Server) Stats() Stats {
	return Stats{
		Connections: s.conns.Load(), Messages: s.msgs.Load(), Rsets: s.rsets.Load(),
		StartTLS: s.starttls.Load(), Commands: s.cmds.Load(), Rejected: s.rejected.Load(),
	}
}

// Messages returns a copy of the messages accepted so far.
func (s *Server) Messages() []Received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Received(nil), s.received...)
}

// WaitMessages blocks until the server has accepted n messages or the timeout
// passes, and reports whether it did.
func (s *Server) WaitMessages(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.msgs.Load() >= int64(n) {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return s.msgs.Load() >= int64(n)
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.done.Load() {
			s.mu.Unlock()
			_ = c.Close()
			return
		}
		s.active[c] = struct{}{}
		s.mu.Unlock()
		n := int(s.conns.Add(1))
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serve(c, n)
			_ = c.Close()
			s.mu.Lock()
			delete(s.active, c)
			s.mu.Unlock()
		}()
	}
}

type session struct {
	s    *Server
	nc   net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer
	n    int
	tls  bool
	helo string

	inMail bool
	from   string
	rcpts  []string
	utf8   bool
	body   string
	bdat   []byte
}

func (se *session) reply(code int, enh, text string) {
	if enh != "" && !se.s.cfg.NoEnhanced {
		text = enh + " " + text
	}
	se.bw.WriteString(strconv.Itoa(code))
	se.bw.WriteByte(' ')
	se.bw.WriteString(text)
	se.bw.WriteString("\r\n")
}

func (se *session) send(r *Reply, defCode int, defEnh, defText string) int {
	if r == nil {
		se.reply(defCode, defEnh, defText)
		return defCode
	}
	se.reply(r.Code, r.Enhanced, r.Text)
	return r.Code
}

func (se *session) flush() error { return se.bw.Flush() }

func (se *session) reset() {
	se.inMail, se.from, se.rcpts, se.utf8, se.body, se.bdat = false, "", se.rcpts[:0], false, "", nil
}

func (s *Server) serve(nc net.Conn, n int) {
	se := &session{s: s, nc: nc, n: n, br: bufio.NewReaderSize(nc, 16<<10), bw: bufio.NewWriterSize(nc, 16<<10)}
	if g := s.cfg.Greeting; g != nil {
		if r := g(n); r != nil {
			se.reply(r.Code, r.Enhanced, r.Text)
			_ = se.flush()
			if r.Code >= 400 {
				return
			}
			goto loop
		}
	}
	se.reply(220, "", s.cfg.Hostname+" ESMTP ready")
	if se.flush() != nil {
		return
	}
loop:
	for {
		_ = nc.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		line, err := se.br.ReadString('\n')
		if err != nil {
			return
		}
		s.cmds.Add(1)
		line = strings.TrimRight(line, "\r\n")
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			if s.cfg.NoEHLO {
				se.reply(502, "5.5.1", "EHLO not implemented")
				break
			}
			se.helo = arg
			se.reset()
			se.ehlo()
		case "HELO":
			se.helo = arg
			se.reset()
			se.reply(250, "", s.cfg.Hostname)
		case "STARTTLS":
			if s.cfg.TLS == nil || se.tls {
				se.reply(502, "5.5.1", "STARTTLS not available")
				break
			}
			se.reply(220, "2.0.0", "ready to start TLS")
			if se.flush() != nil {
				return
			}
			tc := tls.Server(nc, s.cfg.TLS)
			_ = nc.SetDeadline(time.Now().Add(10 * time.Second))
			if err := tc.Handshake(); err != nil {
				return
			}
			s.starttls.Add(1)
			se.nc, se.tls = tc, true
			se.br.Reset(tc)
			se.bw.Reset(tc)
			se.reset()
			se.helo = ""
			nc = tc
			continue loop
		case "MAIL":
			if se.helo == "" {
				se.reply(503, "5.5.1", "say EHLO first")
				break
			}
			if s.cfg.RequireTLS && !se.tls {
				se.reply(530, "5.7.0", "must issue STARTTLS first")
				break
			}
			if se.inMail {
				se.reply(503, "5.5.1", "nested MAIL command")
				break
			}
			from, params, ok := parsePath(arg, "FROM:")
			if !ok {
				se.reply(501, "5.5.4", "syntax error in MAIL")
				break
			}
			if sz := paramValue(params, "SIZE"); sz != "" && s.cfg.Size > 0 {
				if v, err := strconv.ParseInt(sz, 10, 64); err == nil && v > s.cfg.Size {
					s.rejected.Add(1)
					se.reply(552, "5.3.4", "message size exceeds fixed maximum message size")
					break
				}
			}
			if r := hook(s.cfg.OnMail, from); r != nil {
				s.rejected.Add(1)
				se.reply(r.Code, r.Enhanced, r.Text)
				if r.Code == 421 {
					_ = se.flush()
					return
				}
				break
			}
			se.reset()
			se.inMail, se.from = true, from
			se.utf8 = hasParam(params, "SMTPUTF8")
			se.body = paramValue(params, "BODY")
			se.reply(250, "2.1.0", "sender ok")
		case "RCPT":
			if !se.inMail {
				se.reply(503, "5.5.1", "need MAIL before RCPT")
				break
			}
			to, _, ok := parsePath(arg, "TO:")
			if !ok || to == "" {
				se.reply(501, "5.5.4", "syntax error in RCPT")
				break
			}
			if r := hook(s.cfg.OnRcpt, to); r != nil {
				s.rejected.Add(1)
				se.reply(r.Code, r.Enhanced, r.Text)
				if r.Code == 421 {
					_ = se.flush()
					return
				}
				break
			}
			se.rcpts = append(se.rcpts, to)
			se.reply(250, "2.1.5", "recipient ok")
		case "DATA":
			if !se.inMail || len(se.rcpts) == 0 {
				se.reply(503, "5.5.1", "need a valid recipient")
				break
			}
			se.reply(354, "", "end data with <CR><LF>.<CR><LF>")
			if se.flush() != nil {
				return
			}
			data, err := se.readData()
			if err != nil {
				return
			}
			se.finish(data)
		case "BDAT":
			if !se.inMail || len(se.rcpts) == 0 {
				se.reply(503, "5.5.1", "need a valid recipient")
				break
			}
			if !s.cfg.Chunking {
				se.reply(502, "5.5.1", "BDAT not offered")
				break
			}
			sizeStr, rest, _ := strings.Cut(arg, " ")
			size, err := strconv.Atoi(sizeStr)
			if err != nil || size < 0 || size > 64<<20 {
				se.reply(501, "5.5.4", "bad BDAT size")
				break
			}
			chunk := make([]byte, size)
			if _, err := io.ReadFull(se.br, chunk); err != nil {
				return
			}
			se.bdat = append(se.bdat, chunk...)
			if strings.EqualFold(strings.TrimSpace(rest), "LAST") {
				data := se.bdat
				se.bdat = nil
				se.finish(data)
			} else {
				se.reply(250, "2.0.0", strconv.Itoa(size)+" octets received")
			}
		case "RSET":
			s.rsets.Add(1)
			se.reset()
			se.reply(250, "2.0.0", "reset")
		case "NOOP":
			se.reply(250, "2.0.0", "ok")
		case "VRFY":
			se.reply(252, "2.5.2", "cannot verify")
		case "QUIT":
			se.reply(221, "2.0.0", "bye")
			_ = se.flush()
			return
		default:
			se.reply(500, "5.5.2", "command not recognized")
		}
		// Replies to pipelined commands are written together: flush only when
		// the client has nothing more waiting.
		if se.br.Buffered() == 0 || !s.pipelining() {
			if se.flush() != nil {
				return
			}
		}
	}
}

func (s *Server) pipelining() bool { return !s.cfg.NoPipelining }

func hook[T any](f func(T) *Reply, v T) *Reply {
	if f == nil {
		return nil
	}
	return f(v)
}

func (se *session) ehlo() {
	s := se.s
	var lines []string
	lines = append(lines, s.cfg.Hostname+" greets "+se.helo)
	if !s.cfg.NoPipelining {
		lines = append(lines, "PIPELINING")
	}
	lines = append(lines, "8BITMIME")
	if !s.cfg.NoEnhanced {
		lines = append(lines, "ENHANCEDSTATUSCODES")
	}
	if s.cfg.Size > 0 {
		lines = append(lines, "SIZE "+strconv.FormatInt(s.cfg.Size, 10))
	}
	if s.cfg.SMTPUTF8 {
		lines = append(lines, "SMTPUTF8")
	}
	if s.cfg.Chunking {
		lines = append(lines, "CHUNKING")
	}
	if s.cfg.TLS != nil && !se.tls {
		lines = append(lines, "STARTTLS")
	}
	for i, l := range lines {
		sep := "-"
		if i == len(lines)-1 {
			sep = " "
		}
		se.bw.WriteString("250")
		se.bw.WriteString(sep)
		se.bw.WriteString(l)
		se.bw.WriteString("\r\n")
	}
}

// readData reads the DATA payload up to the lone dot, unstuffing leading dots.
func (se *session) readData() ([]byte, error) {
	var buf bytes.Buffer
	for {
		_ = se.nc.SetReadDeadline(time.Now().Add(se.s.cfg.IdleTimeout))
		line, err := se.br.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		if bytes.Equal(line, []byte(".\r\n")) || bytes.Equal(line, []byte(".\n")) {
			return buf.Bytes(), nil
		}
		if len(line) > 0 && line[0] == '.' {
			line = line[1:]
		}
		buf.Write(line)
		if buf.Len() > 64<<20 {
			return nil, errors.New("message too large")
		}
	}
}

func (se *session) finish(data []byte) {
	s := se.s
	m := &Received{
		Seq: int(s.msgs.Load()) + 1, Conn: se.n, Helo: se.helo, From: se.from,
		Rcpts: append([]string(nil), se.rcpts...), Data: data, TLS: se.tls, At: time.Now(),
		Remote: se.nc.RemoteAddr().String(), BodyType: se.body, UTF8: se.utf8,
	}
	var r *Reply
	if s.cfg.OnData != nil {
		r = s.cfg.OnData(m)
	}
	code := se.send(r, 250, "2.0.0", "queued as "+strconv.Itoa(m.Seq))
	if code/100 == 2 {
		s.msgs.Add(1)
		if !s.cfg.Discard {
			s.mu.Lock()
			s.received = append(s.received, *m)
			s.mu.Unlock()
		}
	} else {
		s.rejected.Add(1)
	}
	se.reset()
	if code == 421 {
		_ = se.flush()
		se.nc.Close()
	}
}

// parsePath reads "FROM:<addr> params" or "TO:<addr> params".
func parsePath(arg, prefix string) (addr, params string, ok bool) {
	if len(arg) < len(prefix) || !strings.EqualFold(arg[:len(prefix)], prefix) {
		return "", "", false
	}
	rest := strings.TrimLeft(arg[len(prefix):], " ")
	if !strings.HasPrefix(rest, "<") {
		return "", "", false
	}
	end := strings.IndexByte(rest, '>')
	if end < 0 {
		return "", "", false
	}
	return rest[1:end], strings.TrimSpace(rest[end+1:]), true
}

func paramValue(params, key string) string {
	for _, p := range strings.Fields(params) {
		k, v, _ := strings.Cut(p, "=")
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func hasParam(params, key string) bool {
	for _, p := range strings.Fields(params) {
		k, _, _ := strings.Cut(p, "=")
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

var _ = fmt.Sprintf
