package unit_test

import (
	"context"
	"errors"
	"testing"

	mta "github.com/hyz-is/arandu-mta"
	"github.com/hyz-is/arandu-mta/mtatest"
)

type policies map[string]*mta.MTASTSPolicy

func (p policies) Policy(_ context.Context, domain string) (*mta.MTASTSPolicy, error) {
	return p[domain], nil
}

type failingPolicies struct{}

func (failingPolicies) Policy(context.Context, string) (*mta.MTASTSPolicy, error) {
	return nil, errors.New("policy host unreachable")
}

func TestMTASTSEnforceDeliversOverVerifiedTLS(t *testing.T) {
	tc, pool, err := mtatest.SelfSigned("mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, mtatest.Config{TLS: tc}, func(c *mta.Config) {
		c.RootCAs = pool
		c.MTASTS = policies{"example.com": {Mode: mta.MTASTSEnforce, MX: []string{"mx.example.com"}}}
	})
	h.submit(msg("sts1", "a@example.com"))
	h.events.waitType(t, mta.EventDelivered, 1)
	if !h.srv.Messages()[0].TLS {
		t.Fatal("enforce delivered in plaintext")
	}
	m := h.eng.Metrics()
	if m.MTASTSEnforced.Load() != 1 || m.TLSVerifyFailures.Load() != 0 {
		t.Fatalf("enforced=%d verifyFailures=%d", m.MTASTSEnforced.Load(), m.TLSVerifyFailures.Load())
	}
}

func TestMTASTSEnforceRefusesAnMXOutsideThePolicy(t *testing.T) {
	tc, pool, _ := mtatest.SelfSigned("mx.example.com")
	h := newHarness(t, mtatest.Config{TLS: tc}, func(c *mta.Config) {
		c.RootCAs = pool
		c.MTASTS = policies{"example.com": {Mode: mta.MTASTSEnforce, MX: []string{"*.mail.example.com", "mx.other.test"}}}
	})
	h.submit(msg("sts2", "a@example.com"))
	ev := h.events.waitType(t, mta.EventDeferred, 1)[0]
	if ev.Code != 451 || ev.Enhanced != "4.7.5" || !ev.Local {
		t.Fatalf("event = %+v", ev)
	}
	if h.srv.Stats().Connections != 0 {
		t.Fatal("connected to an MX the policy forbids")
	}
	if h.eng.Metrics().MTASTSRejectedMX.Load() == 0 {
		t.Fatal("rejection not counted")
	}
}

func TestMTASTSEnforceRequiresSTARTTLS(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) {
		c.MTASTS = policies{"example.com": {Mode: mta.MTASTSEnforce, MX: []string{"mx.example.com"}}}
	})
	h.submit(msg("sts3", "a@example.com"))
	ev := h.events.waitType(t, mta.EventDeferred, 1)[0]
	if ev.Enhanced != "4.7.10" {
		t.Fatalf("event = %+v", ev)
	}
	if h.srv.Stats().Messages != 0 {
		t.Fatal("a message was sent in plaintext under an enforcing policy")
	}
}

func TestMTASTSEnforceVerifiesTheCertificate(t *testing.T) {
	tc, _, _ := mtatest.SelfSigned("mx.example.com") // not in the trust roots
	h := newHarness(t, mtatest.Config{TLS: tc}, func(c *mta.Config) {
		c.MTASTS = policies{"example.com": {Mode: mta.MTASTSEnforce, MX: []string{"mx.example.com"}}}
	})
	h.submit(msg("sts4", "a@example.com"))
	ev := h.events.waitType(t, mta.EventDeferred, 1)[0]
	if ev.Enhanced != "4.7.5" {
		t.Fatalf("event = %+v", ev)
	}
	if h.srv.Stats().Messages != 0 {
		t.Fatal("delivered to a server whose certificate does not verify")
	}
	if h.eng.Metrics().TLSVerifyFailures.Load() == 0 {
		t.Fatal("verification failure not counted")
	}
	if h.eng.Metrics().TLSFallbacks.Load() != 0 {
		t.Fatal("enforce must never fall back to plaintext")
	}
}

func TestMTASTSTestingModeDoesNotStopDelivery(t *testing.T) {
	tc, _, _ := mtatest.SelfSigned("mx.example.com")
	h := newHarness(t, mtatest.Config{TLS: tc}, func(c *mta.Config) {
		c.MTASTS = policies{"example.com": {Mode: mta.MTASTSTesting, MX: []string{"mx.example.com"}}}
	})
	h.submit(msg("sts5", "a@example.com"))
	h.events.waitType(t, mta.EventDelivered, 1)
	if h.eng.Metrics().TLSVerifyFailures.Load() == 0 {
		t.Fatal("testing mode should record that verification would have failed")
	}
}

func TestMTASTSLookupErrorDoesNotStopDelivery(t *testing.T) {
	h := newHarness(t, mtatest.Config{}, func(c *mta.Config) { c.MTASTS = failingPolicies{} })
	h.submit(msg("sts6", "a@example.com"))
	h.events.waitType(t, mta.EventDelivered, 1)
	if h.eng.Metrics().MTASTSErrors.Load() != 1 {
		t.Fatal("lookup error not counted")
	}
}

func TestMTASTSPatternMatching(t *testing.T) {
	p := mta.MTASTSPolicy{MX: []string{"mail.example.com", "*.example.net", "MX.Upper.Test."}}
	for host, want := range map[string]bool{
		"mail.example.com":       true,
		"MAIL.example.com.":      true,
		"a.example.net":          true,
		"a.b.example.net":        false, // the wildcard covers one label
		"example.net":            false,
		"xmail.example.com":      false,
		"mx.upper.test":          true,
		"":                       false,
		"evilexample.net":        false,
		"mail.example.com.evil.": false,
	} {
		if got := p.MatchesMX(host); got != want {
			t.Errorf("MatchesMX(%q) = %v, want %v", host, got, want)
		}
	}
	if (mta.MTASTSPolicy{}).MatchesMX("a.test") {
		t.Fatal("a policy without mx lines admits no host")
	}
}
