package mta

import (
	"sync"
	"time"
)

// connPool keeps idle SMTP connections, by exchanger address and source
// address, for the next transaction toward the same server.
type connPool struct {
	mu          sync.Mutex
	idle        map[poolKey][]*smtpConn
	total       int
	maxPerKey   int
	maxTotal    int
	idleTimeout time.Duration
	metrics     *Metrics
	closed      bool
}

func newConnPool(maxPerKey, maxTotal int, idleTimeout time.Duration, m *Metrics) *connPool {
	return &connPool{
		idle:      make(map[poolKey][]*smtpConn),
		maxPerKey: maxPerKey, maxTotal: maxTotal,
		idleTimeout: idleTimeout, metrics: m,
	}
}

// get returns an idle connection for the key, newest first, closing the ones
// that waited too long.
func (p *connPool) get(k poolKey, now time.Time) *smtpConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.idle[k]
	for len(list) > 0 {
		c := list[len(list)-1]
		list[len(list)-1] = nil
		list = list[:len(list)-1]
		p.total--
		p.metrics.IdleConnections.Add(-1)
		if now.Sub(c.idleSince) > p.idleTimeout || c.broken {
			go c.quit()
			continue
		}
		if len(list) == 0 {
			delete(p.idle, k)
		} else {
			p.idle[k] = list
		}
		return c
	}
	delete(p.idle, k)
	return nil
}

// put returns a healthy connection to the pool; false means it was not kept
// and the caller must close it.
func (p *connPool) put(c *smtpConn, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || c.broken || len(p.idle[c.key]) >= p.maxPerKey || p.total >= p.maxTotal {
		return false
	}
	c.idleSince = now
	p.idle[c.key] = append(p.idle[c.key], c)
	p.total++
	p.metrics.IdleConnections.Add(1)
	return true
}

// reap closes the connections idle longer than the timeout.
func (p *connPool) reap(now time.Time) {
	var dead []*smtpConn
	p.mu.Lock()
	for k, list := range p.idle {
		kept := list[:0]
		for _, c := range list {
			if now.Sub(c.idleSince) > p.idleTimeout || c.broken {
				dead = append(dead, c)
				p.total--
				p.metrics.IdleConnections.Add(-1)
			} else {
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			delete(p.idle, k)
		} else {
			p.idle[k] = kept
		}
	}
	p.mu.Unlock()
	for _, c := range dead {
		c.quit()
	}
}

// closeAll closes every idle connection and refuses new ones.
func (p *connPool) closeAll() {
	p.mu.Lock()
	p.closed = true
	var all []*smtpConn
	for k, list := range p.idle {
		all = append(all, list...)
		delete(p.idle, k)
	}
	p.metrics.IdleConnections.Add(-int64(p.total))
	p.total = 0
	p.mu.Unlock()
	for _, c := range all {
		c.quit()
	}
}
