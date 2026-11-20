package unit_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	mta "github.com/hyz-is/arandu-mta"
)

// fakeDNS is a DNS server in the test process, over UDP and TCP on one port.
type fakeDNS struct {
	addr    string
	queries atomic.Int64
	tcp     atomic.Int64
	udp     net.PacketConn
	ln      net.Listener
}

func startFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()
	var s fakeDNS
	var err error
	if s.udp, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	port := s.udp.LocalAddr().(*net.UDPAddr).Port
	if s.ln, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(port))); err != nil {
		t.Fatal(err)
	}
	s.addr = s.udp.LocalAddr().String()
	t.Cleanup(func() { s.udp.Close(); s.ln.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := s.udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := s.answer(buf[:n], true); resp != nil {
				s.udp.WriteTo(resp, from)
			}
		}
	}()
	go func() {
		for {
			c, err := s.ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				s.tcp.Add(1)
				resp := s.answer(q, false)
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out, uint16(len(resp)))
				copy(out[2:], resp)
				c.Write(out)
			}()
		}
	}()
	return &s
}

func (s *fakeDNS) answer(q []byte, udp bool) []byte {
	s.queries.Add(1)
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil
	}
	qs, _ := p.AllQuestions()
	if len(qs) != 1 {
		return nil
	}
	name := qs[0].Name.String()
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true},
		Questions: qs,
	}
	hdr := func(n string, t dnsmessage.Type, ttl uint32) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(n), Type: t, Class: dnsmessage.ClassINET, TTL: ttl}
	}
	mx := func(host string, pref uint16, ttl uint32) dnsmessage.Resource {
		return dnsmessage.Resource{Header: hdr(name, dnsmessage.TypeMX, ttl), Body: &dnsmessage.MXResource{Pref: pref, MX: dnsmessage.MustNewName(host)}}
	}
	switch {
	case qs[0].Type == dnsmessage.TypeMX && name == "example.com.":
		resp.Answers = []dnsmessage.Resource{mx("mx2.example.com.", 20, 120), mx("mx1.example.com.", 10, 300)}
	case qs[0].Type == dnsmessage.TypeMX && name == "short.test.":
		resp.Answers = []dnsmessage.Resource{mx("mx.short.test.", 10, 1)}
	case qs[0].Type == dnsmessage.TypeMX && name == "nullmx.test.":
		resp.Answers = []dnsmessage.Resource{mx(".", 0, 60)}
	case qs[0].Type == dnsmessage.TypeMX && name == "big.test.":
		if udp {
			resp.Truncated = true
		} else {
			for i := 0; i < 30; i++ {
				resp.Answers = append(resp.Answers, mx("mx"+itoa(i)+".big.test.", uint16(i), 60))
			}
		}
	case qs[0].Type == dnsmessage.TypeMX && name == "nomx.test.":
		// NOERROR with no answers: the name exists, without MX records.
	case qs[0].Type == dnsmessage.TypeA && name == "mx1.example.com.":
		resp.Answers = []dnsmessage.Resource{{Header: hdr(name, dnsmessage.TypeA, 60), Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}}
	case qs[0].Type == dnsmessage.TypeAAAA && name == "mx1.example.com.":
		resp.Answers = []dnsmessage.Resource{{Header: hdr(name, dnsmessage.TypeAAAA, 300), Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()}}}
	case qs[0].Type == dnsmessage.TypeA && name == "alias.example.com.":
		resp.Answers = []dnsmessage.Resource{
			{Header: hdr(name, dnsmessage.TypeCNAME, 500), Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("mx1.example.com.")}},
			{Header: hdr("mx1.example.com.", dnsmessage.TypeA, 40), Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}},
		}
	case name == "broken.test.":
		resp.RCode = dnsmessage.RCodeServerFailure
	case qs[0].Type == dnsmessage.TypeA && name == "nomx.test.":
		resp.Answers = []dnsmessage.Resource{{Header: hdr(name, dnsmessage.TypeA, 60), Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 9}}}}
	case name == "mx.short.test.":
		resp.Answers = []dnsmessage.Resource{{Header: hdr(name, dnsmessage.TypeA, 60), Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 2}}}}
	case name == "gone.test.":
		resp.RCode = dnsmessage.RCodeNameError
	default:
		// NOERROR, no data
	}
	out, err := resp.Pack()
	if err != nil {
		return nil
	}
	return out
}

func TestDNSClientCarriesTheTTL(t *testing.T) {
	srv := startFakeDNS(t)
	c := &mta.DNSClient{Servers: []string{srv.addr}, Timeout: time.Second}
	ctx := context.Background()

	mx, err := c.LookupMX(ctx, "example.com")
	if err != nil || len(mx.Records) != 2 || mx.TTL != 120*time.Second {
		t.Fatalf("LookupMX = %+v, %v (TTL is the smallest of the records)", mx, err)
	}
	if mx.Records[0].Host != "mx2.example.com" || mx.Records[0].Pref != 20 {
		t.Fatalf("records = %+v", mx.Records)
	}
	ad, err := c.LookupAddr(ctx, "mx1.example.com")
	if err != nil || len(ad.Addrs) != 2 || ad.TTL != 60*time.Second {
		t.Fatalf("LookupAddr = %+v, %v", ad, err)
	}
	if ad.Addrs[0] != netip.MustParseAddr("192.0.2.1") || ad.Addrs[1] != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("addrs = %v", ad.Addrs)
	}
	al, err := c.LookupAddr(ctx, "alias.example.com")
	if err != nil || len(al.Addrs) != 1 || al.Addrs[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("a name behind a CNAME: %+v, %v", al, err)
	}
}

func TestDNSClientVerdicts(t *testing.T) {
	srv := startFakeDNS(t)
	c := &mta.DNSClient{Servers: []string{srv.addr}, Timeout: 500 * time.Millisecond, Attempts: 1}
	ctx := context.Background()
	if _, err := c.LookupMX(ctx, "gone.test"); !errors.Is(err, mta.ErrNameNotFound) {
		t.Fatalf("NXDOMAIN = %v", err)
	}
	if _, err := c.LookupMX(ctx, "nomx.test"); !errors.Is(err, mta.ErrNameNotFound) {
		t.Fatalf("no data = %v", err)
	}
	if _, err := c.LookupMX(ctx, "broken.test"); !errors.Is(err, mta.ErrDNSTemporary) {
		t.Fatalf("SERVFAIL = %v, want a temporary failure", err)
	}
	if _, err := c.LookupAddr(ctx, "broken.test"); !errors.Is(err, mta.ErrDNSTemporary) {
		t.Fatalf("SERVFAIL for addresses = %v", err)
	}
	if _, err := c.LookupAddr(ctx, "gone.test"); !errors.Is(err, mta.ErrNameNotFound) {
		t.Fatalf("NXDOMAIN for addresses = %v", err)
	}
	dead := &mta.DNSClient{Servers: []string{"127.0.0.1:1"}, Timeout: 100 * time.Millisecond, Attempts: 1}
	if _, err := dead.LookupMX(ctx, "example.com"); !errors.Is(err, mta.ErrDNSTemporary) {
		t.Fatalf("unreachable server = %v", err)
	}
}

func TestDNSClientFallsBackToTCPWhenTruncated(t *testing.T) {
	srv := startFakeDNS(t)
	c := &mta.DNSClient{Servers: []string{srv.addr}, Timeout: time.Second}
	mx, err := c.LookupMX(context.Background(), "big.test")
	if err != nil || len(mx.Records) != 30 {
		t.Fatalf("LookupMX = %d records, %v", len(mx.Records), err)
	}
	if srv.tcp.Load() != 1 {
		t.Fatalf("TCP queries = %d", srv.tcp.Load())
	}
}

func TestDNSClientNullMXThroughTheEngineResolution(t *testing.T) {
	srv := startFakeDNS(t)
	c := &mta.DNSClient{Servers: []string{srv.addr}, Timeout: time.Second}
	mx, err := c.LookupMX(context.Background(), "nullmx.test")
	if err != nil || len(mx.Records) != 1 || mx.Records[0].Host != "" {
		t.Fatalf("null MX = %+v, %v", mx, err)
	}
}

func TestCachedResolverHonoursTheTTLOfTheAnswer(t *testing.T) {
	srv := startFakeDNS(t)
	m := new(mta.Metrics)
	r := mta.NewCachedResolver(&mta.DNSClient{Servers: []string{srv.addr}, Timeout: time.Second}, mta.CacheConfig{MinTTL: time.Millisecond, NegativeTTL: 200 * time.Millisecond}, m)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := r.LookupMX(ctx, "short.test"); err != nil {
			t.Fatal(err)
		}
	}
	if q := srv.queries.Load(); q != 1 {
		t.Fatalf("5 lookups inside the TTL sent %d queries", q)
	}
	if m.DNSCacheHits.Load() != 4 || m.DNSLookups.Load() != 1 {
		t.Fatalf("hits=%d lookups=%d", m.DNSCacheHits.Load(), m.DNSLookups.Load())
	}
	time.Sleep(1100 * time.Millisecond) // the record's TTL is one second
	if _, err := r.LookupMX(ctx, "short.test"); err != nil {
		t.Fatal(err)
	}
	if q := srv.queries.Load(); q != 2 {
		t.Fatalf("after the TTL the answer must be fetched again: %d queries", q)
	}

	// "Not found" is remembered briefly; a hiccup is not remembered at all.
	before := srv.queries.Load()
	for i := 0; i < 3; i++ {
		if _, err := r.LookupMX(ctx, "gone.test"); !errors.Is(err, mta.ErrNameNotFound) {
			t.Fatal(err)
		}
	}
	if srv.queries.Load()-before != 1 {
		t.Fatalf("negative answer not cached: %d queries", srv.queries.Load()-before)
	}
	before = srv.queries.Load()
	for i := 0; i < 2; i++ {
		if _, err := r.LookupMX(ctx, "broken.test"); !errors.Is(err, mta.ErrDNSTemporary) {
			t.Fatal(err)
		}
	}
	if srv.queries.Load()-before < 2 {
		t.Fatal("a temporary failure was cached")
	}
}

func TestCachedResolverSendsOneLookupForConcurrentCallers(t *testing.T) {
	srv := startFakeDNS(t)
	r := mta.NewCachedResolver(&mta.DNSClient{Servers: []string{srv.addr}, Timeout: time.Second}, mta.CacheConfig{}, nil)
	done := make(chan error, 50)
	for i := 0; i < 50; i++ {
		go func() { _, err := r.LookupMX(context.Background(), "example.com"); done <- err }()
	}
	for i := 0; i < 50; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if q := srv.queries.Load(); q != 1 {
		t.Fatalf("50 concurrent lookups sent %d queries", q)
	}
}

func TestResolvConfServers(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/resolv.conf"
	writeFile(t, path, "# comment\nsearch example.test\nnameserver 192.0.2.53\nnameserver 2001:db8::53%eth0\nnameserver not-an-ip\noptions ndots:2\n")
	got, err := mta.ResolvConfServers(path)
	if err != nil || len(got) != 2 || got[0] != "192.0.2.53:53" || got[1] != "[2001:db8::53]:53" {
		t.Fatalf("servers = %v, %v", got, err)
	}
	if _, err := mta.ResolvConfServers(dir + "/missing"); err == nil {
		t.Fatal("missing file accepted")
	}
}
