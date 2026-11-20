package mta

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"sort"
	"sync"
)

// Spool keeps messages durable between the moment the engine accepts them and
// the moment every recipient is settled.
//
// The engine calls Put once per message, Update whenever a recipient changes
// state in a way that must survive a crash, ReadData before each attempt, and
// Delete when the message is complete. A Spool must be safe for concurrent use.
type Spool interface {
	// Put stores the message and its Data. When it returns nil the message is
	// durable. It returns ErrDuplicate when the ID is already stored.
	Put(ctx context.Context, m *Message) error
	// Update replaces the metadata of a stored message; Data is not touched.
	// It returns ErrNotFound when the ID is unknown.
	Update(ctx context.Context, m *Message) error
	// ReadData appends the stored Data of id to buf and returns the result. It
	// returns ErrNotFound when the ID is unknown.
	ReadData(ctx context.Context, id string, buf []byte) ([]byte, error)
	// Delete removes the message and its Data. Deleting an unknown ID is not an
	// error.
	Delete(ctx context.Context, id string) error
	// Load calls fn for every stored message, without Data, in no particular
	// order. The engine uses it at startup to rebuild its index. A message the
	// spool cannot read is skipped and reported by the implementation, never
	// passed to fn half-read. It stops at the first error fn returns.
	Load(ctx context.Context, fn func(*Message) error) error
	// Close releases what the spool holds. Stored messages stay stored.
	Close() error
}

// maxRecipients bounds the recipients of one message, so a corrupt or hostile
// metadata file cannot make the engine allocate without limit.
const maxRecipients = 100_000

// Metadata files start with a one-line header: the format tag, the CRC-32 of
// the JSON body that follows, and a newline. A torn or edited file fails the
// check instead of being half-believed.
const metaMagic = "MTA1 "

// EncodeMeta serializes the metadata of m, Data excluded.
func EncodeMeta(m *Message) ([]byte, error) {
	return AppendMeta(nil, m)
}

// AppendMeta appends the serialized metadata of m to dst.
func AppendMeta(dst []byte, m *Message) ([]byte, error) {
	body, err := json.Marshal(m)
	if err != nil {
		return dst, err
	}
	dst = append(dst, metaMagic...)
	var sum [8]byte
	crc := crc32.ChecksumIEEE(body)
	const hexdigits = "0123456789abcdef"
	for i := 7; i >= 0; i-- {
		sum[i] = hexdigits[crc&0xf]
		crc >>= 4
	}
	dst = append(dst, sum[:]...)
	dst = append(dst, '\n')
	return append(dst, body...), nil
}

// ErrCorruptMeta is returned by DecodeMeta for bytes that are not a valid
// metadata file.
var ErrCorruptMeta = errors.New("mta: corrupt spool metadata")

// DecodeMeta parses what EncodeMeta wrote and checks it: the header, the
// checksum, a valid ID, and sane recipients. It never panics.
func DecodeMeta(b []byte) (*Message, error) {
	if len(b) < len(metaMagic)+9 || string(b[:len(metaMagic)]) != metaMagic {
		return nil, fmt.Errorf("%w: bad header", ErrCorruptMeta)
	}
	hex := b[len(metaMagic) : len(metaMagic)+8]
	if b[len(metaMagic)+8] != '\n' {
		return nil, fmt.Errorf("%w: bad header", ErrCorruptMeta)
	}
	var want uint32
	for _, c := range hex {
		want <<= 4
		switch {
		case c >= '0' && c <= '9':
			want |= uint32(c - '0')
		case c >= 'a' && c <= 'f':
			want |= uint32(c-'a') + 10
		default:
			return nil, fmt.Errorf("%w: bad checksum", ErrCorruptMeta)
		}
	}
	body := b[len(metaMagic)+9:]
	if crc32.ChecksumIEEE(body) != want {
		return nil, fmt.Errorf("%w: checksum mismatch", ErrCorruptMeta)
	}
	var m Message
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptMeta, err)
	}
	if !ValidID(m.ID) {
		return nil, fmt.Errorf("%w: bad id", ErrCorruptMeta)
	}
	if len(m.Recipients) == 0 || len(m.Recipients) > maxRecipients {
		return nil, fmt.Errorf("%w: bad recipient count", ErrCorruptMeta)
	}
	for i := range m.Recipients {
		r := &m.Recipients[i]
		if r.Address == "" || r.State > StateSending {
			return nil, fmt.Errorf("%w: bad recipient", ErrCorruptMeta)
		}
		if r.State == StateSending {
			r.State = StateQueued
		}
	}
	if m.Priority >= priorityLevels {
		return nil, fmt.Errorf("%w: bad priority", ErrCorruptMeta)
	}
	if m.Size < 0 {
		return nil, fmt.Errorf("%w: bad size", ErrCorruptMeta)
	}
	return &m, nil
}

// MemorySpool is a Spool that keeps everything in memory. It is for tests and
// for a node that accepts losing its queue; it is not durable.
type MemorySpool struct {
	mu   sync.RWMutex
	msgs map[string]*memEntry
}

type memEntry struct {
	meta *Message
	data []byte
}

// NewMemorySpool returns an empty MemorySpool.
func NewMemorySpool() *MemorySpool {
	return &MemorySpool{msgs: make(map[string]*memEntry)}
}

// Put implements Spool.
func (s *MemorySpool) Put(_ context.Context, m *Message) error {
	if !ValidID(m.ID) {
		return fmt.Errorf("%w: bad id %q", ErrInvalidMessage, m.ID)
	}
	meta := m.Clone()
	meta.Data = nil
	meta.Size = len(m.Data)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.msgs[m.ID]; ok {
		return ErrDuplicate
	}
	s.msgs[m.ID] = &memEntry{meta: meta, data: bytes.Clone(m.Data)}
	return nil
}

// Update implements Spool.
func (s *MemorySpool) Update(_ context.Context, m *Message) error {
	meta := m.Clone()
	meta.Data = nil
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.msgs[m.ID]
	if !ok {
		return ErrNotFound
	}
	meta.Size = e.meta.Size
	e.meta = meta
	return nil
}

// ReadData implements Spool.
func (s *MemorySpool) ReadData(_ context.Context, id string, buf []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.msgs[id]
	if !ok {
		return buf, ErrNotFound
	}
	return append(buf, e.data...), nil
}

// Delete implements Spool.
func (s *MemorySpool) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	delete(s.msgs, id)
	s.mu.Unlock()
	return nil
}

// Load implements Spool.
func (s *MemorySpool) Load(ctx context.Context, fn func(*Message) error) error {
	s.mu.RLock()
	ids := make([]string, 0, len(s.msgs))
	for id := range s.msgs {
		ids = append(ids, id)
	}
	s.mu.RUnlock()
	sort.Strings(ids)
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.mu.RLock()
		e, ok := s.msgs[id]
		var meta *Message
		if ok {
			meta = e.meta.Clone()
		}
		s.mu.RUnlock()
		if !ok {
			continue
		}
		if err := fn(meta); err != nil {
			return err
		}
	}
	return nil
}

// Close implements Spool.
func (s *MemorySpool) Close() error { return nil }

// Len returns how many messages are stored.
func (s *MemorySpool) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.msgs)
}
