package mta

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DiskSpoolOptions tunes a DiskSpool.
type DiskSpoolOptions struct {
	// NoSync turns every fsync off. A crash can then lose accepted messages and
	// repeat deliveries; it exists for tests and benchmarks.
	NoSync bool
}

// DiskSpool is a Spool that keeps one data file and one metadata file per
// message under a directory.
//
// Layout, under the directory given to OpenDiskSpool:
//
//	<xx>/<id>.eml    the message, written once
//	<xx>/<id>.meta   the metadata, replaced on every Update
//	corrupt/         what Load could not read, moved aside
//
// where <xx> is two hex digits of a hash of the ID, which keeps a directory
// from growing without bound. Every write goes to a temporary file in the same
// directory, is fsynced, and is renamed into place; the directory is fsynced
// after the renames. The metadata file is what makes a message exist: the data
// file is renamed first, so a crash leaves either nothing or a complete pair,
// and a lone data file or temporary file is removed by the next open.
type DiskSpool struct {
	dir    string
	noSync bool

	mu   sync.Mutex // guards dirs
	dirs map[string]*os.File

	seq        atomic.Uint64
	recovered  atomic.Int64
	quarantine atomic.Int64
	closed     atomic.Bool
}

const (
	dataExt = ".eml"
	metaExt = ".meta"
	tmpTag  = ".tmp-"
)

// OpenDiskSpool opens, or creates, a spool in dir and cleans up what a crash
// left behind: temporary files and data files without metadata.
func OpenDiskSpool(dir string, opts DiskSpoolOptions) (*DiskSpool, error) {
	if dir == "" {
		return nil, errors.New("mta: disk spool needs a directory")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("mta: create spool: %w", err)
	}
	s := &DiskSpool{dir: dir, noSync: opts.NoSync, dirs: make(map[string]*os.File)}
	if err := s.sweep(); err != nil {
		return nil, err
	}
	return s, nil
}

// Dir returns the spool directory.
func (s *DiskSpool) Dir() string { return s.dir }

// Quarantined returns how many unreadable messages Load moved aside since the
// spool was opened.
func (s *DiskSpool) Quarantined() int { return int(s.quarantine.Load()) }

// Swept returns how many leftovers the open removed: temporary files and
// orphan data files.
func (s *DiskSpool) Swept() int { return int(s.recovered.Load()) }

func shardOf(id string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	const hexdigits = "0123456789abcdef"
	v := h.Sum32()
	return string([]byte{hexdigits[(v>>4)&0xf], hexdigits[v&0xf]})
}

func (s *DiskSpool) shardDir(id string) string { return filepath.Join(s.dir, shardOf(id)) }

func (s *DiskSpool) dataPath(id string) string {
	return filepath.Join(s.shardDir(id), id+dataExt)
}

func (s *DiskSpool) metaPath(id string) string {
	return filepath.Join(s.shardDir(id), id+metaExt)
}

// sweep removes temporary files and data files that have no metadata.
func (s *DiskSpool) sweep() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("mta: read spool: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() || len(e.Name()) != 2 {
			continue
		}
		shard := filepath.Join(s.dir, e.Name())
		files, err := os.ReadDir(shard)
		if err != nil {
			return fmt.Errorf("mta: read spool shard: %w", err)
		}
		have := make(map[string]bool, len(files))
		for _, f := range files {
			if strings.HasSuffix(f.Name(), metaExt) {
				have[strings.TrimSuffix(f.Name(), metaExt)] = true
			}
		}
		for _, f := range files {
			name := f.Name()
			switch {
			case strings.HasPrefix(name, ".") && strings.Contains(name, tmpTag):
				_ = os.Remove(filepath.Join(shard, name))
				s.recovered.Add(1)
			case strings.HasSuffix(name, dataExt) && !have[strings.TrimSuffix(name, dataExt)]:
				_ = os.Remove(filepath.Join(shard, name))
				s.recovered.Add(1)
			}
		}
	}
	return nil
}

// syncDir fsyncs a shard directory so renames and removals in it are durable.
func (s *DiskSpool) syncDir(path string) error {
	if s.noSync {
		return nil
	}
	s.mu.Lock()
	d, ok := s.dirs[path]
	if !ok {
		var err error
		d, err = os.Open(path)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		s.dirs[path] = d
	}
	s.mu.Unlock()
	if err := d.Sync(); err != nil {
		// Some filesystems refuse fsync on a directory; the data is as durable
		// as the filesystem makes it.
		var pe *fs.PathError
		if errors.As(err, &pe) && (errors.Is(err, os.ErrInvalid) || strings.Contains(err.Error(), "invalid argument")) {
			return nil
		}
		return err
	}
	return nil
}

func (s *DiskSpool) tmpName(dir, id string) string {
	return filepath.Join(dir, "."+id+tmpTag+strconv.FormatUint(s.seq.Add(1), 36)+"-"+strconv.FormatInt(time.Now().UnixNano(), 36))
}

// writeAtomic writes b to path through a temporary file in the same directory.
func (s *DiskSpool) writeAtomic(path, id string, b []byte) error {
	tmp := s.tmpName(filepath.Dir(path), id)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil && !s.noSync {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

var metaBufs = sync.Pool{New: func() any { b := make([]byte, 0, 1024); return &b }}

// Put implements Spool.
func (s *DiskSpool) Put(_ context.Context, m *Message) error {
	if !ValidID(m.ID) {
		return fmt.Errorf("%w: bad id %q", ErrInvalidMessage, m.ID)
	}
	dir := s.shardDir(m.ID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if _, err := os.Lstat(s.metaPath(m.ID)); err == nil {
		return ErrDuplicate
	}
	meta := *m
	meta.Size = len(m.Data)
	bp := metaBufs.Get().(*[]byte)
	defer func() { *bp = (*bp)[:0]; metaBufs.Put(bp) }()
	encoded, err := AppendMeta((*bp)[:0], &meta)
	if err != nil {
		return err
	}
	*bp = encoded
	if err := s.writeAtomic(s.dataPath(m.ID), m.ID, m.Data); err != nil {
		return err
	}
	if err := s.writeAtomic(s.metaPath(m.ID), m.ID, encoded); err != nil {
		_ = os.Remove(s.dataPath(m.ID))
		return err
	}
	return s.syncDir(dir)
}

// Update implements Spool.
func (s *DiskSpool) Update(_ context.Context, m *Message) error {
	if !ValidID(m.ID) {
		return fmt.Errorf("%w: bad id %q", ErrInvalidMessage, m.ID)
	}
	if _, err := os.Lstat(s.metaPath(m.ID)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	// The size is a fact about the data file, which Update does not touch.
	st, err := os.Stat(s.dataPath(m.ID))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	meta := *m
	meta.Size = int(st.Size())
	bp := metaBufs.Get().(*[]byte)
	defer func() { *bp = (*bp)[:0]; metaBufs.Put(bp) }()
	encoded, err := AppendMeta((*bp)[:0], &meta)
	if err != nil {
		return err
	}
	*bp = encoded
	if err := s.writeAtomic(s.metaPath(m.ID), m.ID, encoded); err != nil {
		return err
	}
	return s.syncDir(s.shardDir(m.ID))
}

// ReadData implements Spool.
func (s *DiskSpool) ReadData(_ context.Context, id string, buf []byte) ([]byte, error) {
	if !ValidID(id) {
		return buf, ErrNotFound
	}
	f, err := os.Open(s.dataPath(id))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return buf, ErrNotFound
		}
		return buf, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return buf, err
	}
	n := int(st.Size())
	start := len(buf)
	if cap(buf)-start < n {
		grown := make([]byte, start, start+n)
		copy(grown, buf)
		buf = grown
	}
	buf = buf[:start+n]
	if _, err := io.ReadFull(f, buf[start:]); err != nil {
		return buf[:start], err
	}
	return buf, nil
}

// Delete implements Spool.
func (s *DiskSpool) Delete(_ context.Context, id string) error {
	if !ValidID(id) {
		return nil
	}
	if err := os.Remove(s.metaPath(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Remove(s.dataPath(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return s.syncDir(s.shardDir(id))
}

// Load implements Spool.
func (s *DiskSpool) Load(ctx context.Context, fn func(*Message) error) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() || len(e.Name()) != 2 {
			continue
		}
		shard := filepath.Join(s.dir, e.Name())
		files, err := os.ReadDir(shard)
		if err != nil {
			return err
		}
		for _, f := range files {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := f.Name()
			if !strings.HasSuffix(name, metaExt) || strings.HasPrefix(name, ".") {
				continue
			}
			id := strings.TrimSuffix(name, metaExt)
			b, err := os.ReadFile(filepath.Join(shard, name))
			var m *Message
			if err == nil {
				m, err = DecodeMeta(b)
			}
			if err == nil && m.ID != id {
				err = fmt.Errorf("%w: id does not match file name", ErrCorruptMeta)
			}
			if err == nil {
				st, serr := os.Stat(s.dataPath(id))
				switch {
				case serr != nil:
					err = fmt.Errorf("%w: data file missing", ErrCorruptMeta)
				case m.Size != 0 && st.Size() != int64(m.Size):
					err = fmt.Errorf("%w: data file has %d bytes, metadata says %d", ErrCorruptMeta, st.Size(), m.Size)
				}
			}
			if err != nil {
				s.quarantineMessage(id)
				continue
			}
			if err := fn(m); err != nil {
				return err
			}
		}
	}
	return nil
}

// quarantineMessage moves an unreadable pair out of the live directories.
func (s *DiskSpool) quarantineMessage(id string) {
	dst := filepath.Join(s.dir, "corrupt")
	if err := os.MkdirAll(dst, 0o750); err != nil {
		return
	}
	for _, ext := range []string{metaExt, dataExt} {
		src := filepath.Join(s.shardDir(id), id+ext)
		_ = os.Rename(src, filepath.Join(dst, id+ext))
	}
	s.quarantine.Add(1)
}

// Close implements Spool.
func (s *DiskSpool) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var first error
	for p, d := range s.dirs {
		if err := d.Close(); err != nil && first == nil {
			first = err
		}
		delete(s.dirs, p)
	}
	return first
}
