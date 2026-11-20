package unit_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mta "github.com/hyz-is/arandu-mta"
	"github.com/hyz-is/arandu-mta/mtatest"
)

func TestDeliversWith250(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, nil)
	h.submit(msg("m1", "ana@example.com"))
	ev := h.events.waitType(t, mta.EventDelivered, 1)[0]
	if ev.Code != 250 || ev.Enhanced != "2.0.0" || ev.MX != "mx.example.com" || ev.Recipient != "ana@example.com" || ev.MessageID != "m1" || ev.Tenant != "org_1" {
		t.Fatalf("event = %+v", ev)
	}
	got := h.srv.Messages()
	if len(got) != 1 || got[0].From != "bounce+m1@mail.sender.test" || len(got[0].Rcpts) != 1 {
		t.Fatalf("server saw %+v", got)
	}
	if !strings.Contains(string(got[0].Data), "Subject: m1") || !strings.HasSuffix(string(got[0].Data), "Hello m1.\r\n") {
		t.Fatalf("data = %q", got[0].Data)
	}
	if err := h.eng.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := h.spool.(*mta.MemorySpool).Len(); n != 0 {
		t.Fatalf("spool still holds %d messages after delivery", n)
	}
}

func TestTemporaryFailureIsRetriedAndDelivered(t *testing.T) {
	var calls atomic.Int32
	h := newHarness(t, mtatest.Config{OnData: func(*mtatest.Received) *mtatest.Reply {
		if calls.Add(1) == 1 {
			return rep(451, "4.3.0", "mail system busy, try again")
		}
		return nil
	}}, nil)
	h.submit(msg("m2", "ana@example.com"))
	h.events.waitType(t, mta.EventDelivered, 1)
	def := h.events.ofType(mta.EventDeferred)
	if len(def) != 1 {
		t.Fatalf("want 1 deferred event, got %s", describe(h.events.all()))
	}
	d := def[0]
	if d.Code != 451 || d.Enhanced != "4.3.0" || d.Attempt != 1 || d.NextAttempt.IsZero() || d.Class.Permanent || d.Class.Type != mta.BounceTransient {
		t.Fatalf("deferred event = %+v", d)
	}
	del := h.events.ofType(mta.EventDelivered)[0]
	if del.Attempt != 2 {
		t.Fatalf("delivered on attempt %d, want 2", del.Attempt)
	}
	if got := h.eng.Metrics().Deferred.Load(); got != 1 {
		t.Fatalf("deferred metric = %d", got)
	}
}

func TestPermanentFailureBounces(t *testing.T) {
	h := newHarness(t, mtatest.Config{OnRcpt: func(string) *mtatest.Reply {
		return rep(550, "5.1.1", "<ghost@example.com>: Recipient address rejected: User unknown")
	}}, nil)
	h.submit(msg("m3", "ghost@example.com"))
	ev := h.events.waitType(t, mta.EventBounced, 1)[0]
	if ev.Code != 550 || ev.Enhanced != "5.1.1" || ev.Class.Type != mta.BouncePermanent || ev.Class.SubType != mta.SubNoEmail || !ev.Class.Permanent {
		t.Fatalf("event = %+v", ev)
	}
	if h.srv.Stats().Messages != 0 {
		t.Fatal("a rejected recipient must not cause a message to be sent")
	}
	if err := h.eng.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.spool.(*mta.MemorySpool).Len() != 0 {
		t.Fatal("bounced message left in spool")
	}
}

func TestPartialFailureWithSeveralRecipients(t *testing.T) {
	var tries sync.Map
	h := newHarness(t, mtatest.Config{OnRcpt: func(to string) *mtatest.Reply {
		switch to {
		case "gone@example.com":
			return rep(550, "5.1.1", "no such user")
		case "busy@example.com":
			n, _ := tries.LoadOrStore(to, new(atomic.Int32))
			if n.(*atomic.Int32).Add(1) == 1 {
				return rep(452, "4.2.2", "mailbox is full")
			}
		}
		return nil
	}}, nil)
	h.submit(msg("m4", "ok@example.com", "gone@example.com", "busy@example.com"))

	h.events.wait(t, "final outcomes", func(ev []mta.Event) bool {
		d, b := 0, 0
		for _, e := range ev {
			if e.Type == mta.EventDelivered {
				d++
			}
			if e.Type == mta.EventBounced {
				b++
			}
		}
		return d == 2 && b == 1
	})
	byRcpt := map[string][]mta.Event{}
	for _, e := range h.events.all() {
		byRcpt[e.Recipient] = append(byRcpt[e.Recipient], e)
	}
	if got := byRcpt["gone@example.com"]; len(got) != 1 || got[0].Type != mta.EventBounced || got[0].Class.SubType != mta.SubNoEmail {
		t.Fatalf("gone: %s", describe(got))
	}
	busy := byRcpt["busy@example.com"]
	if len(busy) != 2 || busy[0].Type != mta.EventDeferred || busy[0].Class.SubType != mta.SubMailboxFull || busy[1].Type != mta.EventDelivered || busy[1].Attempt != 2 {
		t.Fatalf("busy: %s", describe(busy))
	}
	if ok := byRcpt["ok@example.com"]; len(ok) != 1 || ok[0].Type != mta.EventDelivered || ok[0].Attempt != 1 {
		t.Fatalf("ok: %s", describe(ok))
	}
	msgs := h.srv.Messages()
	if len(msgs) != 2 || len(msgs[0].Rcpts) != 1 || msgs[0].Rcpts[0] != "ok@example.com" || len(msgs[1].Rcpts) != 1 || msgs[1].Rcpts[0] != "busy@example.com" {
		t.Fatalf("server messages: first %v, then %v (want [ok] then [busy])", msgs[0].Rcpts, msgs[len(msgs)-1].Rcpts)
	}
}

func TestDataRejectionBouncesEveryAcceptedRecipient(t *testing.T) {
	h := newHarness(t, mtatest.Config{OnData: func(*mtatest.Received) *mtatest.Reply {
		return rep(554, "5.7.1", "Message rejected as spam by content filter")
	}}, nil)
	h.submit(msg("m5", "a@example.com", "b@example.com"))
	evs := h.events.waitType(t, mta.EventBounced, 2)
	for _, e := range evs {
		if e.Code != 554 || e.Class.SubType != mta.SubContentRejected {
			t.Fatalf("event = %+v", e)
		}
	}
}

func TestOneTransactionPerDomainWithManyRecipients(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, nil, "example.com", "example.org")
	h.submit(msg("m6", "a@example.com", "b@example.com", "c@example.org", "d@example.com"))
	h.events.waitType(t, mta.EventDelivered, 4)
	got := h.srv.Messages()
	if len(got) != 2 {
		t.Fatalf("want 2 transactions (one per domain), got %d", len(got))
	}
	sizes := map[int]bool{len(got[0].Rcpts): true, len(got[1].Rcpts): true}
	if !sizes[3] || !sizes[1] {
		t.Fatalf("recipients per transaction = %d and %d, want 3 and 1", len(got[0].Rcpts), len(got[1].Rcpts))
	}
}

func TestDotStuffingAndLineEndings(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, nil)
	m := msg("m7", "a@example.com")
	m.Data = []byte("Subject: dots\n\n.leading dot\n..two dots\nno final newline")
	h.submit(m)
	h.events.waitType(t, mta.EventDelivered, 1)
	got := h.srv.Messages()[0].Data
	want := []byte("Subject: dots\r\n\r\n.leading dot\r\n..two dots\r\nno final newline\r\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("server received %q, want %q", got, want)
	}
}

func TestConnectionIsReusedWithRSET(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, nil)
	for i := 0; i < 5; i++ {
		h.submit(msg("reuse"+string(rune('a'+i)), "a@example.com"))
		h.events.waitType(t, mta.EventDelivered, i+1)
	}
	st := h.srv.Stats()
	if st.Connections != 1 || st.Messages != 5 {
		t.Fatalf("server saw %d connections and %d messages, want 1 and 5", st.Connections, st.Messages)
	}
	if st.Rsets != 4 {
		t.Fatalf("RSET count = %d, want 4 (one per reuse)", st.Rsets)
	}
	if got := h.eng.Metrics().ConnectionsReused.Load(); got != 4 {
		t.Fatalf("reused metric = %d", got)
	}
}

func TestStaleIdleConnectionIsReplaced(t *testing.T) {
	// The server closes connections that idle for 80ms; the engine keeps them in
	// its pool for 30s, so the next transaction finds a dead connection.
	h := newHarness(t, mtatest.Config{IdleTimeout: 80 * time.Millisecond}, nil)
	h.submit(msg("s1", "a@example.com"))
	h.events.waitType(t, mta.EventDelivered, 1)
	time.Sleep(250 * time.Millisecond)
	h.submit(msg("s2", "a@example.com"))
	h.events.waitType(t, mta.EventDelivered, 2)
	if got := h.eng.Metrics().ConnectionsStale.Load(); got != 1 {
		t.Fatalf("stale connections noticed = %d, want 1", got)
	}
	if got := h.srv.Stats().Connections; got != 2 {
		t.Fatalf("server connections = %d, want 2", got)
	}
	for _, e := range h.events.ofType(mta.EventDeferred) {
		t.Fatalf("a dead pooled connection must not defer the message: %+v", e)
	}
}

func TestSTARTTLSWithSelfSignedCertificate(t *testing.T) {
	tc, _, err := mtatest.SelfSigned("mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, mtatest.Config{TLS: tc}, nil)
	h.submit(msg("t1", "a@example.com"))
	h.events.waitType(t, mta.EventDelivered, 1)
	got := h.srv.Messages()[0]
	if !got.TLS {
		t.Fatal("message arrived in plaintext although the server offered STARTTLS")
	}
	m := h.eng.Metrics()
	if m.TLSHandshakes.Load() != 1 {
		t.Fatalf("handshakes = %d", m.TLSHandshakes.Load())
	}
	if m.TLSVerifyFailures.Load() != 1 {
		t.Fatalf("an unverifiable certificate must be counted, got %d", m.TLSVerifyFailures.Load())
	}
}

func TestSTARTTLSCanBeDisabled(t *testing.T) {
	tc, _, _ := mtatest.SelfSigned("mx.example.com")
	h := newHarness(t, mtatest.Config{TLS: tc}, func(c *mta.Config) { c.DisableSTARTTLS = true })
	h.submit(msg("t2", "a@example.com"))
	h.events.waitType(t, mta.EventDelivered, 1)
	if h.srv.Messages()[0].TLS {
		t.Fatal("STARTTLS was used although disabled")
	}
}

func TestBrokenSTARTTLSFallsBackToPlaintext(t *testing.T) {
	// The server offers STARTTLS but can only speak TLS 1.1, which the client
	// refuses: the handshake fails, and opportunistic TLS must not stop the mail.
	tc, _, _ := mtatest.SelfSigned("mx.example.com")
	tc.MaxVersion = tls.VersionTLS11
	h := newHarness(t, mtatest.Config{TLS: tc}, nil)
	h.submit(msg("t3", "a@example.com"))
	h.events.waitType(t, mta.EventDelivered, 1)
	if h.srv.Messages()[0].TLS {
		t.Fatal("message was reported as TLS although the handshake cannot have succeeded")
	}
	if got := h.eng.Metrics().TLSFallbacks.Load(); got != 1 {
		t.Fatalf("fallbacks = %d, want 1", got)
	}
	if got := h.srv.Stats().Connections; got != 2 {
		t.Fatalf("connections = %d, want 2 (failed TLS, then plaintext)", got)
	}
}

func TestNullMXBouncesWithoutConnecting(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, nil)
	h.res.AddMX("nomail.test", mta.MX{Host: ".", Pref: 0})
	h.submit(msg("n1", "a@nomail.test"))
	ev := h.events.waitType(t, mta.EventBounced, 1)[0]
	if ev.Code != 556 || ev.Enhanced != "5.1.10" || !ev.Local || !ev.Class.Permanent {
		t.Fatalf("event = %+v", ev)
	}
	if h.srv.Stats().Connections != 0 {
		t.Fatal("connected to a domain that publishes a null MX")
	}
	if h.eng.Metrics().NullMX.Load() != 1 {
		t.Fatal("null MX not counted")
	}
}

func TestUnknownDomainBounces(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, nil)
	h.submit(msg("d1", "a@does-not-exist.test"))
	ev := h.events.waitType(t, mta.EventBounced, 1)[0]
	if ev.Code != 550 || ev.Enhanced != "5.1.2" || ev.Class.SubType != mta.SubNoEmail {
		t.Fatalf("event = %+v", ev)
	}
}

func TestImplicitMXUsesTheDomainItself(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, nil)
	// No MX records, but the domain has an address: RFC 5321 section 5.1.
	h.res.AddHost("implicit.test", "127.0.0.1")
	h.submit(msg("i1", "a@implicit.test"))
	ev := h.events.waitType(t, mta.EventDelivered, 1)[0]
	if ev.MX != "implicit.test" {
		t.Fatalf("delivered via %q", ev.MX)
	}
}

func TestTemporaryDNSFailureDefers(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, nil)
	h.res.Fail("flaky.test", errors.Join(mta.ErrDNSTemporary, errors.New("servfail")))
	h.submit(msg("f1", "a@flaky.test"))
	ev := h.events.waitType(t, mta.EventDeferred, 1)[0]
	if ev.Code != 451 || ev.Enhanced != "4.4.3" || !ev.Local {
		t.Fatalf("event = %+v", ev)
	}
}

func TestMXPreferenceOrderAndFallback(t *testing.T) {
	good, err := mtatest.Start(mtatest.Config{Hostname: "mx2.multi.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) {
		c.Dial = func(ctx context.Context, tg mta.DialTarget) (net_Conn, error) {
			switch tg.Host {
			case "mx1.multi.test": // nothing listens there
				return dialTCP(ctx, "127.0.0.1:1")
			case "mx2.multi.test":
				return dialTCP(ctx, good.Addr())
			}
			return dialTCP(ctx, tg.Addr.String()+":"+itoa(tg.Port))
		}
	})
	h.res.AddMX("multi.test", mta.MX{Host: "mx2.multi.test", Pref: 20}, mta.MX{Host: "mx1.multi.test", Pref: 10})
	h.res.AddHost("mx1.multi.test", "127.0.0.1").AddHost("mx2.multi.test", "127.0.0.1")
	h.submit(msg("x1", "a@multi.test"))
	ev := h.events.waitType(t, mta.EventDelivered, 1)[0]
	if ev.MX != "mx2.multi.test" {
		t.Fatalf("delivered via %q, want the second MX after the first refused", ev.MX)
	}
	if good.Stats().Messages != 1 {
		t.Fatal("backup MX did not get the message")
	}
	if h.eng.Metrics().ConnectionsFailed.Load() == 0 {
		t.Fatal("the failed connection was not counted")
	}
}

func TestBannerRejectionOnEveryMXDefers(t *testing.T) {
	h := newHarness(t, mtatest.Config{Greeting: func(int) *mtatest.Reply { return rep(554, "", "no SMTP service here") }}, nil)
	h.submit(msg("b1", "a@example.com"))
	ev := h.events.waitType(t, mta.EventDeferred, 1)[0]
	if ev.Code != 554 {
		t.Fatalf("event = %+v", ev)
	}
}

func TestRetryWindowEndsInABounce(t *testing.T) {
	h := newHarness(t, mtatest.Config{OnData: func(*mtatest.Received) *mtatest.Reply {
		return rep(451, "4.7.1", "greylisted, please come back")
	}}, func(c *mta.Config) {
		c.Expiry = 120 * time.Millisecond
		c.Backoff = mta.Backoff{Schedule: []time.Duration{40 * time.Millisecond}, Jitter: -1}
	})
	h.submit(msg("e1", "a@example.com"))
	ev := h.events.waitType(t, mta.EventBounced, 1)[0]
	if !ev.Expired || !strings.Contains(ev.Text, "expired") || !strings.Contains(ev.Text, "greylisted") {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Class.Type != mta.BounceTransient {
		t.Fatalf("an expired message after temporary failures is a transient bounce, got %s", ev.Class.Type)
	}
	if ev.Attempt < 2 {
		t.Fatalf("attempts = %d; the engine must retry before it gives up", ev.Attempt)
	}
	if h.eng.Metrics().Expired.Load() != 1 {
		t.Fatal("expiry not counted")
	}
}

func TestSuppressedRecipientBouncesWithoutSending(t *testing.T) {
	sup := mta.SuppressionFunc(func(_ context.Context, tenant, addr string) (bool, string) {
		return addr == "no@example.com" && tenant == "org_1", "hard bounce on 2026-11-01"
	})
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) { c.Suppression = sup })
	h.submit(msg("su1", "no@example.com", "yes@example.com"))
	h.events.waitType(t, mta.EventDelivered, 1)
	b := h.events.waitType(t, mta.EventBounced, 1)[0]
	if !b.Suppressed || b.Class.SubType != mta.SubSuppressed || b.Recipient != "no@example.com" || !b.Local {
		t.Fatalf("event = %+v", b)
	}
	if got := h.srv.Messages(); len(got) != 1 || len(got[0].Rcpts) != 1 || got[0].Rcpts[0] != "yes@example.com" {
		t.Fatalf("server messages: %+v", got)
	}
}

func TestSignerSignsOnSubmitWhenADomainIsGiven(t *testing.T) {
	signer := mta.SignerFunc(func(_ context.Context, domain string, data []byte) ([]byte, error) {
		return append([]byte("DKIM-Signature: d="+domain+"\r\n"), data...), nil
	})
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) { c.Signer = signer })
	m := msg("sg1", "a@example.com")
	m.DKIMDomain = "sender.test"
	h.submit(m)
	h.submit(msg("sg2", "a@example.com"))
	h.events.waitType(t, mta.EventDelivered, 2)
	for _, got := range h.srv.Messages() {
		signed := strings.HasPrefix(string(got.Data), "DKIM-Signature: d=sender.test\r\n")
		if strings.Contains(string(got.Data), "Subject: sg1") != signed {
			t.Fatalf("message %q: signed=%v", got.Data, signed)
		}
	}
	bad := mta.SignerFunc(func(context.Context, string, []byte) ([]byte, error) { return nil, errors.New("no key") })
	h2 := newHarness(t, mtatest.Config{}, func(c *mta.Config) { c.Signer = bad })
	m = msg("sg3", "a@example.com")
	m.DKIMDomain = "sender.test"
	var se *mta.SignError
	if err := h2.eng.Submit(context.Background(), m); !errors.As(err, &se) {
		t.Fatalf("Submit error = %v, want *SignError", err)
	}
}

func TestSizeLimitAnnouncedByServerIsHonoured(t *testing.T) {
	h := newHarness(t, mtatest.Config{Size: 200}, nil)
	m := msg("z1", "a@example.com")
	m.Data = append(m.Data, bytes.Repeat([]byte("x"), 400)...)
	h.submit(m)
	ev := h.events.waitType(t, mta.EventBounced, 1)[0]
	if ev.Code != 552 || ev.Enhanced != "5.3.4" || ev.Class.SubType != mta.SubMessageTooLarge || !ev.Local {
		t.Fatalf("event = %+v", ev)
	}
	if h.srv.Stats().Commands > 3 {
		t.Fatalf("the engine sent %d commands for a message it knew was too large", h.srv.Stats().Commands)
	}
}

func TestChunkingWithBDAT(t *testing.T) {
	h := newHarness(t, mtatest.Config{Chunking: true}, func(c *mta.Config) { c.UseChunking = true })
	m := msg("c1", "a@example.com", "b@example.com")
	m.Data = []byte("Subject: bdat\r\n\r\n.starts with a dot\r\nbody\r\n")
	h.submit(m)
	h.events.waitType(t, mta.EventDelivered, 2)
	got := h.srv.Messages()[0]
	if string(got.Data) != string(m.Data) {
		t.Fatalf("BDAT payload = %q", got.Data)
	}
}

func TestOldServerWithoutEHLONorPipelining(t *testing.T) {
	h := newHarness(t, mtatest.Config{NoEHLO: true, NoPipelining: true}, nil)
	h.submit(msg("o1", "a@example.com", "b@example.com"))
	h.events.waitType(t, mta.EventDelivered, 2)
}

func TestPipeliningDisabledOnTheClient(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) { c.DisablePipelining = true })
	h.submit(msg("p1", "a@example.com", "b@example.com", "c@example.com"))
	h.events.waitType(t, mta.EventDelivered, 3)
}

func TestSMTPUTF8(t *testing.T) {
	h := newHarness(t, mtatest.Config{SMTPUTF8: true}, nil)
	h.submit(msg("u1", "josé@example.com"))
	h.events.waitType(t, mta.EventDelivered, 1)
	got := h.srv.Messages()[0]
	if !got.UTF8 || got.Rcpts[0] != "josé@example.com" {
		t.Fatalf("server saw %+v", got)
	}

	h2 := newHarness(t, mtatest.Config{}, nil)
	h2.submit(msg("u2", "josé@example.com", "plain@example.com"))
	b := h2.events.waitType(t, mta.EventBounced, 1)[0]
	if b.Code != 553 || b.Enhanced != "5.6.7" || b.Recipient != "josé@example.com" {
		t.Fatalf("event = %+v", b)
	}
	h2.events.waitType(t, mta.EventDelivered, 1)
}

func TestEightBitBodyIsDeclared(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, nil)
	m := msg("e8", "a@example.com")
	m.Data = []byte("Subject: caf\xc3\xa9\r\n\r\ncaf\xc3\xa9\r\n")
	h.submit(m)
	h.events.waitType(t, mta.EventDelivered, 1)
	if got := h.srv.Messages()[0].BodyType; got != "8BITMIME" {
		t.Fatalf("BODY = %q", got)
	}
}

func TestSubmitValidation(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, nil)
	ctx := context.Background()
	for name, m := range map[string]*mta.Message{
		"no id":       {Data: []byte("x"), Recipients: []mta.Recipient{{Address: "a@example.com"}}},
		"bad id":      {ID: "../etc", Data: []byte("x"), Recipients: []mta.Recipient{{Address: "a@example.com"}}},
		"no data":     {ID: "v1", Recipients: []mta.Recipient{{Address: "a@example.com"}}},
		"no rcpt":     {ID: "v2", Data: []byte("x")},
		"bad rcpt":    {ID: "v3", Data: []byte("x"), Recipients: []mta.Recipient{{Address: "not an address"}}},
		"rcpt crlf":   {ID: "v4", Data: []byte("x"), Recipients: []mta.Recipient{{Address: "a@example.com\r\nDATA"}}},
		"bad from":    {ID: "v5", MailFrom: "a@b>\r\n", Data: []byte("x"), Recipients: []mta.Recipient{{Address: "a@example.com"}}},
		"bad prio":    {ID: "v6", Priority: 9, Data: []byte("x"), Recipients: []mta.Recipient{{Address: "a@example.com"}}},
		"angle rcpt":  {ID: "v7", Data: []byte("x"), Recipients: []mta.Recipient{{Address: "<a@example.com>"}}},
		"empty local": {ID: "v8", Data: []byte("x"), Recipients: []mta.Recipient{{Address: "@example.com"}}},
	} {
		err := h.eng.Submit(ctx, m)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	h.submit(msg("dup", "a@example.com"))
	h.events.waitType(t, mta.EventDelivered, 1)
	// A completed message leaves the queue, so its ID is free again; a queued one
	// is not.
	h.srv.Close()
	h.submit(msg("dup2", "a@example.com"))
	if err := h.eng.Submit(ctx, msg("dup2", "a@example.com")); !errors.Is(err, mta.ErrDuplicate) {
		t.Fatalf("second Submit of a queued id = %v, want ErrDuplicate", err)
	}
}

func TestDuplicateRecipientsAreSentOnce(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, nil)
	h.submit(msg("dr", "a@example.com", "A@Example.com", "b@example.com"))
	h.events.waitType(t, mta.EventDelivered, 2)
	if got := h.srv.Messages()[0].Rcpts; len(got) != 2 {
		t.Fatalf("recipients on the wire: %v", got)
	}
}

func TestSubmitBeforeStartAndAfterShutdown(t *testing.T) {
	e, err := mta.New(mta.Config{Spool: mta.NewMemorySpool()})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Submit(context.Background(), msg("s", "a@example.com")); !errors.Is(err, mta.ErrNotStarted) {
		t.Fatalf("before Start: %v", err)
	}
	h := newHarness(t, mtatest.Config{}, nil)
	if err := h.eng.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.eng.Submit(context.Background(), msg("s2", "a@example.com")); !errors.Is(err, mta.ErrClosed) {
		t.Fatalf("after Shutdown: %v", err)
	}
	if err := h.eng.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

func TestNewRejectsAConfigWithoutASpool(t *testing.T) {
	if _, err := mta.New(mta.Config{}); err == nil {
		t.Fatal("New accepted a config without a spool")
	}
}

func TestChunkingCoversPartialAndTotalRejection(t *testing.T) {
	for name, srv := range map[string]mtatest.Config{
		"pipelined":     {Chunking: true},
		"not pipelined": {Chunking: true, NoPipelining: true},
	} {
		t.Run(name, func(t *testing.T) {
			srv.OnRcpt = func(to string) *mtatest.Reply {
				if strings.HasPrefix(to, "bad") {
					return rep(550, "5.1.1", "no such user")
				}
				return nil
			}
			h := newHarness(t, srv, func(c *mta.Config) { c.UseChunking = true })
			h.submit(msg("ch1", "good@example.com", "bad1@example.com"))
			h.submit(msg("ch2", "bad2@example.com"))
			h.events.waitType(t, mta.EventDelivered, 1)
			h.events.waitType(t, mta.EventBounced, 2)
			if got := h.srv.Stats().Messages; got != 1 {
				t.Fatalf("server accepted %d messages, want 1", got)
			}
			// The connection is still in step after the rejected chunk: another
			// message goes through it.
			h.submit(msg("ch3", "good@example.com"))
			h.events.waitType(t, mta.EventDelivered, 2)
		})
	}
}
