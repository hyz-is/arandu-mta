package mta

import (
	"container/heap"
	"time"
)

// item is one unit of scheduled work: the recipients of one message that share
// a destination domain, delivered in one SMTP transaction.
type item struct {
	e      *entry
	domain string
	prio   Priority
}

// deque is a FIFO of items that reuses its storage.
type deque struct {
	buf  []*item
	head int
}

func (d *deque) push(it *item) { d.buf = append(d.buf, it) }

func (d *deque) len() int { return len(d.buf) - d.head }

func (d *deque) pop() *item {
	if d.head >= len(d.buf) {
		return nil
	}
	it := d.buf[d.head]
	d.buf[d.head] = nil
	d.head++
	switch {
	case d.head == len(d.buf):
		d.buf, d.head = d.buf[:0], 0
	case d.head >= 4096 && d.head*2 >= len(d.buf):
		n := copy(d.buf, d.buf[d.head:])
		clear(d.buf[n:])
		d.buf, d.head = d.buf[:n], 0
	}
	return it
}

// queueRing is a FIFO of domain queues that wait for a worker.
type queueRing struct {
	buf  []*domainQ
	head int
}

func (r *queueRing) push(q *domainQ) { r.buf = append(r.buf, q) }

func (r *queueRing) len() int { return len(r.buf) - r.head }

func (r *queueRing) pop() *domainQ {
	if r.head >= len(r.buf) {
		return nil
	}
	q := r.buf[r.head]
	r.buf[r.head] = nil
	r.head++
	switch {
	case r.head == len(r.buf):
		r.buf, r.head = r.buf[:0], 0
	case r.head >= 1024 && r.head*2 >= len(r.buf):
		n := copy(r.buf, r.buf[r.head:])
		clear(r.buf[n:])
		r.buf, r.head = r.buf[:n], 0
	}
	return q
}

// domainQ is the queue of one destination domain and the limits that govern it.
type domainQ struct {
	name   string
	ready  [priorityLevels]deque
	nready int
	// items counts every live item of the domain: ready, delayed and running.
	items int
	// active is the workers serving the domain now; tokens the entries it has in
	// the run queue.
	active, tokens int

	cfgMax   int
	maxConns int
	perMin   int
	burst    int
	bucket   *TokenBucket

	level       int
	calm        int
	pausedUntil time.Time
	wakeAt      time.Time
}

// timerEntry is a wake-up: either an item whose retry time has come, or a
// domain whose pause or rate limit ends.
type timerEntry struct {
	at  time.Time
	seq uint64
	it  *item
	dq  *domainQ
}

type timerHeap []timerEntry

func (h timerHeap) Len() int { return len(h) }
func (h timerHeap) Less(i, j int) bool {
	if h[i].at.Equal(h[j].at) {
		return h[i].seq < h[j].seq
	}
	return h[i].at.Before(h[j].at)
}
func (h timerHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *timerHeap) Push(x any)   { *h = append(*h, x.(timerEntry)) }
func (h *timerHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = timerEntry{}
	*h = old[:n-1]
	return x
}

func (h *timerHeap) add(e timerEntry) (first bool) {
	heap.Push(h, e)
	return (*h)[0].seq == e.seq
}
