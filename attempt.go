package otpauth

import "sync"

type AttemptBook struct {
	mu sync.Mutex
	n  map[string]int
}

func NewAttemptBook() *AttemptBook {
	return &AttemptBook{n: make(map[string]int)}
}

func (a *AttemptBook) Note(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n[id]++
}

func (a *AttemptBook) Count(id string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n[id]
}
