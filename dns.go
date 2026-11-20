package mta

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNSClient is a Resolver that speaks DNS itself, so that answers carry the
// TTL the zone published. The standard library's resolver hides it, and a
// CachedResolver over it can only guess.
//
// It sends recursive queries over UDP and retries over TCP when the answer is
// truncated. It does not validate DNSSEC, and it trusts the recursive resolver
// it is pointed at.
type DNSClient struct {
	// Servers are the recursive resolvers, "host:port" or a bare address for
	// port 53. Empty means the nameservers of /etc/resolv.conf.
	Servers []string
	// Timeout bounds one exchange with one server. Zero means 3 seconds.
	Timeout time.Duration
	// Attempts is how many rounds over the servers are made. Zero means 2.
	Attempts int
	// Dial opens the socket; nil uses net.Dialer. Tests replace it.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	once    sync.Once
	servers []string
}

// ResolvConfServers returns the nameservers listed in a resolv.conf file, each
// as "address:53".
func ResolvConfServers(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if a, err := netip.ParseAddr(strings.SplitN(fields[1], "%", 2)[0]); err == nil {
				out = append(out, netip.AddrPortFrom(a, 53).String())
			}
		}
	}
	return out, sc.Err()
}

func (c *DNSClient) serverList() []string {
	c.once.Do(func() {
		for _, s := range c.Servers {
			if _, _, err := net.SplitHostPort(s); err != nil {
				s = net.JoinHostPort(s, "53")
			}
			c.servers = append(c.servers, s)
		}
		if len(c.servers) == 0 {
			c.servers, _ = ResolvConfServers("/etc/resolv.conf")
		}
	})
	return c.servers
}

// rr is the part of a resource record the engine reads.
type rr struct {
	name string
	ttl  uint32
	body dnsmessage.ResourceBody
}

// query asks for one name and type and returns the answer section.
func (c *DNSClient) query(ctx context.Context, name string, typ dnsmessage.Type) ([]rr, error) {
	servers := c.serverList()
	if len(servers) == 0 {
		return nil, fmt.Errorf("%w: no nameservers configured", ErrDNSTemporary)
	}
	dn, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNameNotFound, err)
	}
	attempts := c.Attempts
	if attempts <= 0 {
		attempts = 2
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	var last error
	for a := 0; a < attempts; a++ {
		for _, srv := range servers {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			answers, err := c.exchange(ctx, srv, timeout, dn, typ)
			if err == nil {
				return answers, nil
			}
			if errors.Is(err, ErrNameNotFound) {
				return nil, err
			}
			last = err
		}
	}
	return nil, fmt.Errorf("%w: %v", ErrDNSTemporary, last)
}

func (c *DNSClient) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func (c *DNSClient) exchange(ctx context.Context, server string, timeout time.Duration, name dnsmessage.Name, typ dnsmessage.Type) ([]rr, error) {
	var idb [2]byte
	if _, err := crand.Read(idb[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	req := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: typ, Class: dnsmessage.ClassINET}},
	}
	wire, err := req.Pack()
	if err != nil {
		return nil, err
	}
	resp, err := c.roundTrip(ctx, "udp", server, timeout, wire)
	if err != nil {
		return nil, err
	}
	msg, err := parseResponse(resp, id, name, typ)
	if err != nil {
		return nil, err
	}
	if msg.Truncated {
		if resp, err = c.roundTrip(ctx, "tcp", server, timeout, wire); err != nil {
			return nil, err
		}
		if msg, err = parseResponse(resp, id, name, typ); err != nil {
			return nil, err
		}
	}
	switch msg.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, fmt.Errorf("%w: %s", ErrNameNotFound, strings.TrimSuffix(name.String(), "."))
	default:
		return nil, fmt.Errorf("server %s answered %v", server, msg.RCode)
	}
	var out []rr
	for _, a := range msg.answers {
		out = append(out, rr{name: strings.ToLower(a.Header.Name.String()), ttl: a.Header.TTL, body: a.Body})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s has no %v record", ErrNameNotFound, strings.TrimSuffix(name.String(), "."), typ)
	}
	return out, nil
}

type parsedResponse struct {
	dnsmessage.Header
	answers []dnsmessage.Resource
}

func parseResponse(wire []byte, id uint16, name dnsmessage.Name, typ dnsmessage.Type) (*parsedResponse, error) {
	var p dnsmessage.Parser
	h, err := p.Start(wire)
	if err != nil {
		return nil, err
	}
	if h.ID != id || !h.Response {
		return nil, errors.New("reply does not match the query")
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return nil, err
	}
	if len(qs) != 1 || qs[0].Type != typ || !strings.EqualFold(qs[0].Name.String(), name.String()) {
		return nil, errors.New("reply answers another question")
	}
	answers, err := p.AllAnswers()
	if err != nil && !h.Truncated {
		return nil, err
	}
	return &parsedResponse{Header: h, answers: answers}, nil
}

func (c *DNSClient) roundTrip(ctx context.Context, network, server string, timeout time.Duration, wire []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := c.dial(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if network == "tcp" {
		buf := make([]byte, 2+len(wire))
		binary.BigEndian.PutUint16(buf, uint16(len(wire)))
		copy(buf[2:], wire)
		if _, err := conn.Write(buf); err != nil {
			return nil, err
		}
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, err
		}
		return resp, nil
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, err
	}
	return resp[:n], nil
}

// LookupMX implements Resolver.
func (c *DNSClient) LookupMX(ctx context.Context, domain string) (MXAnswer, error) {
	answers, err := c.query(ctx, domain, dnsmessage.TypeMX)
	if err != nil {
		return MXAnswer{}, err
	}
	var out MXAnswer
	minTTL := ^uint32(0)
	for _, a := range answers {
		mx, ok := a.body.(*dnsmessage.MXResource)
		if !ok {
			continue
		}
		host := strings.TrimSuffix(strings.ToLower(mx.MX.String()), ".")
		out.Records = append(out.Records, MX{Host: host, Pref: mx.Pref})
		minTTL = min(minTTL, a.ttl)
	}
	if len(out.Records) == 0 {
		return MXAnswer{}, fmt.Errorf("%w: %s has no MX record", ErrNameNotFound, domain)
	}
	out.TTL = time.Duration(minTTL) * time.Second
	return out, nil
}

// LookupAddr implements Resolver. It asks for A and AAAA at once and follows a
// CNAME chain as far as the answer carries it.
func (c *DNSClient) LookupAddr(ctx context.Context, host string) (AddrAnswer, error) {
	type result struct {
		rrs []rr
		err error
	}
	var res [2]result
	var wg sync.WaitGroup
	for i, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res[i].rrs, res[i].err = c.query(ctx, host, typ)
		}()
	}
	wg.Wait()
	var out AddrAnswer
	minTTL := ^uint32(0)
	for _, r := range res {
		for _, a := range r.rrs {
			var ip netip.Addr
			switch b := a.body.(type) {
			case *dnsmessage.AResource:
				ip = netip.AddrFrom4(b.A)
			case *dnsmessage.AAAAResource:
				ip = netip.AddrFrom16(b.AAAA)
			default:
				continue
			}
			out.Addrs = append(out.Addrs, ip)
			minTTL = min(minTTL, a.ttl)
		}
	}
	if len(out.Addrs) > 0 {
		out.TTL = time.Duration(minTTL) * time.Second
		return out, nil
	}
	// No address. "Not found" only when neither type is a hiccup.
	for _, r := range res {
		if r.err != nil && !errors.Is(r.err, ErrNameNotFound) {
			return AddrAnswer{}, r.err
		}
	}
	return AddrAnswer{}, fmt.Errorf("%w: %s has no address", ErrNameNotFound, host)
}
