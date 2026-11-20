package unit_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	mta "github.com/hyz-is/arandu-mta"
	"github.com/hyz-is/arandu-mta/mtatest"
)

// eventLog is an EventSink that keeps what it receives.
type eventLog struct {
	mu     sync.Mutex
	events []mta.Event
}

func (l *eventLog) Emit(_ context.Context, ev mta.Event) error {
	l.mu.Lock()
	l.events = append(l.events, ev)
	l.mu.Unlock()
	return nil
}

func (l *eventLog) all() []mta.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]mta.Event(nil), l.events...)
}

func (l *eventLog) ofType(t mta.EventType) []mta.Event {
	var out []mta.Event
	for _, e := range l.all() {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

// wait blocks until cond is true for the events, or fails the test.
func (l *eventLog) wait(t testing.TB, what string, cond func([]mta.Event) bool) []mta.Event {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ev := l.all(); cond(ev) {
			return ev
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s; events so far: %s", what, describe(l.all()))
	return nil
}

func (l *eventLog) waitType(t testing.TB, typ mta.EventType, n int) []mta.Event {
	t.Helper()
	l.wait(t, fmt.Sprintf("%d %s events", n, typ), func(ev []mta.Event) bool {
		c := 0
		for _, e := range ev {
			if e.Type == typ {
				c++
			}
		}
		return c >= n
	})
	return l.ofType(typ)
}

func describe(evs []mta.Event) string {
	var b strings.Builder
	for _, e := range evs {
		fmt.Fprintf(&b, "[%s %s %d %s %q] ", e.Type, e.Recipient, e.Code, e.Enhanced, e.Text)
	}
	return b.String()
}

// harness is an engine wired to one fake server and a table resolver.
type harness struct {
	t      testing.TB
	eng    *mta.Engine
	srv    *mtatest.Server
	res    *mtatest.Resolver
	events *eventLog
	spool  mta.Spool
}

func fastBackoff() mta.Backoff {
	return mta.Backoff{Schedule: []time.Duration{20 * time.Millisecond, 30 * time.Millisecond, 40 * time.Millisecond}, Jitter: -1}
}

// newHarness starts a server with srvCfg and an engine configured by mod. Every
// domain in domains routes to the server.
func newHarness(t testing.TB, srvCfg mtatest.Config, mod func(*mta.Config), domains ...string) *harness {
	t.Helper()
	srv, err := mtatest.Start(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	res := mtatest.NewResolver()
	if len(domains) == 0 {
		domains = []string{"example.com"}
	}
	for _, d := range domains {
		res.Route(d, "mx."+d)
	}
	h := &harness{t: t, srv: srv, res: res, events: &eventLog{}, spool: mta.NewMemorySpool()}
	cfg := mta.Config{
		Spool: h.spool, Resolver: res, Events: h.events,
		Port: srv.Port(), EHLOName: "mta.test", Workers: 16,
		Backoff: fastBackoff(), Expiry: 10 * time.Second,
		Timeouts: mta.Timeouts{Connect: 2 * time.Second, Greeting: 5 * time.Second, Command: 5 * time.Second, DataInit: 5 * time.Second, DataBlock: 5 * time.Second, DataTermination: 5 * time.Second},
		Adaptive: mta.AdaptiveConfig{BasePause: 40 * time.Millisecond, MaxPause: 200 * time.Millisecond, RecoverAfter: 3},
	}
	if mod != nil {
		mod(&cfg)
	}
	if cfg.Spool != h.spool {
		h.spool = cfg.Spool
	}
	h.eng, err = mta.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.eng.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.eng.Shutdown(ctx)
	})
	return h
}

func msg(id string, rcpts ...string) *mta.Message {
	m := &mta.Message{
		ID: id, Tenant: "org_1", MailFrom: "bounce+" + id + "@mail.sender.test",
		Data: []byte("From: Sender <hello@sender.test>\r\nTo: " + strings.Join(rcpts, ", ") + "\r\nSubject: " + id + "\r\nMessage-ID: <" + id + "@sender.test>\r\n\r\nHello " + id + ".\r\n"),
	}
	for _, r := range rcpts {
		m.Recipients = append(m.Recipients, mta.Recipient{Address: r})
	}
	return m
}

func (h *harness) submit(m *mta.Message) {
	h.t.Helper()
	if err := h.eng.Submit(context.Background(), m); err != nil {
		h.t.Fatalf("Submit(%s): %v", m.ID, err)
	}
}

func rep(code int, enh, text string) *mtatest.Reply {
	return &mtatest.Reply{Code: code, Enhanced: enh, Text: text}
}

func tempDir(t testing.TB) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "spool")
	if err := os.MkdirAll(d, 0o750); err != nil {
		t.Fatal(err)
	}
	return d
}

var _ = net.IPv4len

type net_Conn = net.Conn

func dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

func itoa(n int) string { return fmt.Sprint(n) }

type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (a *atomicBool) set(v bool) { a.mu.Lock(); a.v = v; a.mu.Unlock() }
func (a *atomicBool) get() bool  { a.mu.Lock(); defer a.mu.Unlock(); return a.v }

func newFuzzResolver() *mtatest.Resolver {
	return mtatest.NewResolver().Route("fuzz.test", "mx.fuzz.test")
}

func writeFile(t testing.TB, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// startFakeDNSForFuzz returns a well-formed DNS response, to seed fuzzing.
func startFakeDNSForFuzz(f *testing.F) []byte {
	var s fakeDNS
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeMX, Class: dnsmessage.ClassINET}},
	}
	wire, _ := q.Pack()
	return s.answer(wire, true)
}
