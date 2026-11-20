package mtatest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mta "github.com/hyz-is/arandu-mta"
)

// Resolver answers from tables. A domain absent from MX has no MX records; a
// host absent from Addrs does not exist. Err makes a name fail with that error.
type Resolver struct {
	mu    sync.Mutex
	mx    map[string][]mta.MX
	addrs map[string][]netip.Addr
	errs  map[string]error
	ttl   time.Duration

	MXLookups   atomic.Int64
	AddrLookups atomic.Int64
}

// NewResolver returns an empty resolver.
func NewResolver() *Resolver {
	return &Resolver{mx: map[string][]mta.MX{}, addrs: map[string][]netip.Addr{}, errs: map[string]error{}}
}

// SetTTL sets the TTL every answer carries.
func (r *Resolver) SetTTL(d time.Duration) { r.mu.Lock(); r.ttl = d; r.mu.Unlock() }

// AddMX sets the MX records of a domain.
func (r *Resolver) AddMX(domain string, mx ...mta.MX) *Resolver {
	r.mu.Lock()
	r.mx[strings.ToLower(domain)] = mx
	r.mu.Unlock()
	return r
}

// AddHost sets the addresses of a host name.
func (r *Resolver) AddHost(host string, addrs ...string) *Resolver {
	r.mu.Lock()
	for _, a := range addrs {
		r.addrs[strings.ToLower(host)] = append(r.addrs[strings.ToLower(host)], netip.MustParseAddr(a))
	}
	r.mu.Unlock()
	return r
}

// Fail makes lookups of name return err, for both MX and addresses.
func (r *Resolver) Fail(name string, err error) *Resolver {
	r.mu.Lock()
	r.errs[strings.ToLower(name)] = err
	r.mu.Unlock()
	return r
}

// Route is the common case: domain has one MX named host, which lives at
// 127.0.0.1.
func (r *Resolver) Route(domain, host string) *Resolver {
	return r.AddMX(domain, mta.MX{Host: host, Pref: 10}).AddHost(host, "127.0.0.1")
}

// LookupMX implements mta.Resolver.
func (r *Resolver) LookupMX(_ context.Context, domain string) (mta.MXAnswer, error) {
	r.MXLookups.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	domain = strings.ToLower(domain)
	if err, ok := r.errs[domain]; ok {
		return mta.MXAnswer{}, err
	}
	recs, ok := r.mx[domain]
	if !ok {
		return mta.MXAnswer{}, fmt.Errorf("%w: %s", mta.ErrNameNotFound, domain)
	}
	return mta.MXAnswer{Records: append([]mta.MX(nil), recs...), TTL: r.ttl}, nil
}

// LookupAddr implements mta.Resolver.
func (r *Resolver) LookupAddr(_ context.Context, host string) (mta.AddrAnswer, error) {
	r.AddrLookups.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	host = strings.ToLower(host)
	if err, ok := r.errs[host]; ok {
		return mta.AddrAnswer{}, err
	}
	a, ok := r.addrs[host]
	if !ok {
		return mta.AddrAnswer{}, fmt.Errorf("%w: %s", mta.ErrNameNotFound, host)
	}
	return mta.AddrAnswer{Addrs: append([]netip.Addr(nil), a...), TTL: r.ttl}, nil
}

// SelfSigned makes a self-signed certificate valid for the given host names and
// 127.0.0.1. It returns the server configuration and a pool that trusts it.
func SelfSigned(hosts ...string) (*tls.Config, *x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mtatest"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              hosts,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}, pool, nil
}
