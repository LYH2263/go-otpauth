package otpauth

import (
	"crypto/rand"
	"encoding/base32"
	"sync"
)

type Registry struct {
	mu      sync.Mutex
	secrets map[string][]byte
	closed  bool
}

func NewRegistry() *Registry {
	return &Registry{secrets: make(map[string][]byte)}
}

func (r *Registry) Register(id string, secret []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if id == "" || len(secret) == 0 {
		return ErrInvalid
	}
	cp := make([]byte, len(secret))
	copy(cp, secret)
	r.secrets[id] = cp
	return nil
}

func (r *Registry) Get(id string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrClosed
	}
	s, ok := r.secrets[id]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]byte, len(s))
	copy(out, s)
	return out, nil
}

func (r *Registry) ListIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.secrets))
	for id := range r.secrets {
		out = append(out, id)
	}
	return out
}

func (r *Registry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.secrets = nil
}

func RandomSecret(n int) (string, []byte, error) {
	if n <= 0 {
		n = 20
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), b, nil
}
