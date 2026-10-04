package broker

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/asuhacoder/handkey/internal/cryptobox"
)

type store struct {
	dir  string
	key  []byte
	lock *os.File
}

func openStore(dir string) (*store, State, error) {
	empty := State{Version: 1, Devices: map[string]*Device{}, Requests: map[string]*Request{}, Cache: map[string]Item{}}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, empty, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, empty, errors.New("state directory must be private (0700), without symlinks")
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, empty, err
	}
	if err = lockFile(f); err != nil {
		f.Close()
		return nil, empty, errors.New("state directory is already in use")
	}
	s := &store{dir: dir, lock: f}
	s.key, err = os.ReadFile(filepath.Join(dir, "state.key"))
	if os.IsNotExist(err) {
		if _, e := os.Stat(filepath.Join(dir, "state.enc")); e == nil {
			s.close()
			return nil, empty, errors.New("state key is missing; restore the complete backup")
		}
		s.key = cryptobox.Random(32)
		err = atomicWrite(filepath.Join(dir, "state.key"), s.key)
	}
	if err != nil || len(s.key) != 32 {
		s.close()
		return nil, empty, errors.New("cannot load state key")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "state.enc"))
	if os.IsNotExist(err) {
		return s, empty, nil
	}
	if err != nil {
		s.close()
		return nil, empty, err
	}
	data, err := cryptobox.Open(s.key, raw, "handkey-state-v1")
	if err != nil {
		s.close()
		return nil, empty, err
	}
	defer cryptobox.Wipe(data)
	if err = json.Unmarshal(data, &empty); err != nil {
		s.close()
		return nil, empty, errors.New("invalid state")
	}
	if empty.Version != 1 || empty.Devices == nil || empty.Requests == nil || empty.Cache == nil {
		s.close()
		return nil, empty, errors.New("unsupported state format")
	}
	return s, empty, nil
}
func (s *store) close() {
	cryptobox.Wipe(s.key)
	if s.lock != nil {
		s.lock.Close()
	}
}
func atomicWrite(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".state-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	return syncDir(filepath.Dir(path))
}
func (s *store) save(state *State) error {
	data, e := json.Marshal(state)
	if e != nil {
		return e
	}
	defer cryptobox.Wipe(data)
	enc, e := cryptobox.Seal(s.key, data, "handkey-state-v1")
	if e != nil {
		return e
	}
	return atomicWrite(filepath.Join(s.dir, "state.enc"), enc)
}

// The audit schema deliberately has no free-form text, values, or command output.
type Audit struct {
	At      time.Time `json:"at"`
	Request string    `json:"request"`
	Kind    string    `json:"kind"`
	Method  string    `json:"method,omitempty"`
	Refs    []Ref     `json:"refs,omitempty"`
	Origin  string    `json:"origin,omitempty"`
	Device  string    `json:"device,omitempty"`
	TTL     int       `json:"ttl_seconds,omitempty"`
	Uses    int       `json:"uses,omitempty"`
}

func (s *store) audit(a Audit) error {
	f, e := os.OpenFile(filepath.Join(s.dir, "audit.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = json.NewEncoder(f).Encode(a); e != nil {
		return e
	}
	return f.Sync()
}

type events struct {
	mu   sync.Mutex
	next int
	subs map[int]chan Event
}

func (e *events) subscribe() (<-chan Event, func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.subs == nil {
		e.subs = map[int]chan Event{}
	}
	e.next++
	id := e.next
	c := make(chan Event, 32)
	e.subs[id] = c
	return c, func() { e.mu.Lock(); delete(e.subs, id); e.mu.Unlock() }
}
func (e *events) send(v Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.subs {
		select {
		case c <- v:
		default:
		}
	}
}
