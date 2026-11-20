package mta

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"strconv"
)

// connFailure is a connection that could not be made ready for a transaction.
type connFailure struct {
	reply Reply
}

func tempLocal(enhanced, text string) *connFailure {
	return &connFailure{reply: localReply(451, enhanced, text)}
}

// connect opens a connection to host at addr, reads the banner, says EHLO and
// negotiates STARTTLS. strict is true under an enforcing MTA-STS policy: the
// connection must be encrypted and the certificate must verify for host.
func connect(ctx context.Context, o *clientOpts, host string, addr, local netip.Addr, ehlo string, strict bool) (*smtpConn, *connFailure) {
	tryTLS := !o.noSTARTTLS
	for {
		c, fail, tlsFailed := connectOnce(ctx, o, host, addr, local, ehlo, strict, tryTLS)
		if tlsFailed && !strict && tryTLS {
			// Opportunistic TLS that fails is retried in plaintext, the way mail
			// servers do, because a broken STARTTLS must not stop the mail.
			o.metrics.TLSFallbacks.Add(1)
			tryTLS = false
			continue
		}
		return c, fail
	}
}

func connectOnce(ctx context.Context, o *clientOpts, host string, addr, local netip.Addr, ehlo string, strict, tryTLS bool) (c *smtpConn, fail *connFailure, tlsFailed bool) {
	nc, err := o.dial(ctx, DialTarget{Host: host, Addr: addr, Port: o.port, Local: local, Timeout: o.timeouts.Connect})
	if err != nil {
		o.metrics.ConnectionsFailed.Add(1)
		return nil, tempLocal("4.4.1", "connection to "+host+" ["+addr.String()+"] failed: "+err.Error()), false
	}
	o.metrics.ConnectionsOpened.Add(1)
	c = &smtpConn{
		nc: nc, br: bufio.NewReaderSize(nc, readBufSize), bw: bufio.NewWriterSize(nc, writeBufSize),
		host: host, addr: addr, ehlo: ehlo,
		key: poolKey{host: host, addr: addr, local: local, strict: strict},
	}
	// Close the connection when the engine is told to stop waiting.
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	defer func() {
		if !stop() && fail == nil {
			// The context fired while we were finishing; the connection is gone.
			c.broken = true
			fail = tempLocal("4.4.1", "connection to "+host+" interrupted")
			c = nil
		}
	}()

	fail = func() *connFailure {
		rep, err := c.greeting(o)
		if err != nil {
			return tempLocal("4.4.1", "no banner from "+host+": "+err.Error())
		}
		if rep.Code != 0 && rep.Code != 220 {
			return &connFailure{reply: rep}
		}
		rep, err = c.hello(o)
		if err != nil {
			return tempLocal("4.4.1", "EHLO to "+host+" failed: "+err.Error())
		}
		if rep.Code/100 != 2 {
			return &connFailure{reply: rep}
		}
		if !c.caps.STARTTLS {
			if strict {
				return tempLocal("4.7.10", "MTA-STS requires TLS but "+host+" does not offer STARTTLS")
			}
			return nil
		}
		if !tryTLS {
			if strict {
				return tempLocal("4.7.10", "MTA-STS requires TLS but STARTTLS was not tried for "+host)
			}
			return nil
		}
		c.setDeadline(o.timeouts.Command)
		if err := c.command("STARTTLS"); err != nil {
			return tempLocal("4.4.1", "STARTTLS to "+host+" failed: "+err.Error())
		}
		code, text, err := c.readReply()
		if err != nil {
			return tempLocal("4.4.1", "STARTTLS to "+host+" failed: "+err.Error())
		}
		if code != 220 {
			if strict {
				r := buildReply(code, text)
				return tempLocal("4.7.10", "MTA-STS requires TLS but "+host+" refused STARTTLS: "+strconv.Itoa(r.Code)+" "+r.Text)
			}
			return nil // stay in plaintext
		}
		tc := o.tlsConfig(host, strict)
		tconn := tls.Client(nc, tc)
		_ = nc.SetDeadline(deadlineAfter(o.timeouts.Command))
		if err := tconn.HandshakeContext(ctx); err != nil {
			tlsFailed = true
			var ce *tls.CertificateVerificationError
			if errors.As(err, &ce) {
				o.metrics.TLSVerifyFailures.Add(1)
			}
			if strict {
				return tempLocal("4.7.5", "TLS to "+host+" failed under MTA-STS: "+err.Error())
			}
			return tempLocal("4.7.5", "TLS to "+host+" failed: "+err.Error())
		}
		o.metrics.TLSHandshakes.Add(1)
		c.nc = tconn
		c.br.Reset(tconn)
		c.bw.Reset(tconn)
		c.tls = true
		c.verified = strict
		rep, err = c.hello(o)
		if err != nil {
			return tempLocal("4.4.1", "EHLO after STARTTLS to "+host+" failed: "+err.Error())
		}
		if rep.Code/100 != 2 {
			return &connFailure{reply: rep}
		}
		return nil
	}()
	if fail != nil {
		c.close()
		return nil, fail, tlsFailed
	}
	return c, nil, false
}

func (o *clientOpts) tlsConfig(host string, strict bool) *tls.Config {
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            o.rootCAs,
		ClientSessionCache: o.sessions,
	}
	if strict {
		return cfg
	}
	// Opportunistic: encrypt, accept what the server presents, and count the
	// certificates that would not have verified.
	cfg.InsecureSkipVerify = true
	roots := o.rootCAs
	m := o.metrics
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			m.TLSVerifyFailures.Add(1)
			return nil
		}
		opts := x509.VerifyOptions{DNSName: cs.ServerName, Roots: roots, Intermediates: x509.NewCertPool()}
		for _, ic := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(ic)
		}
		if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
			m.TLSVerifyFailures.Add(1)
		}
		return nil
	}
	return cfg
}

var _ net.Conn = (*tls.Conn)(nil)
