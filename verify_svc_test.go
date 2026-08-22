package otpauth

import (
	"errors"
	"testing"

	"github.com/LYH2263/go-otpauth/internal/clock"
)

// A nil Clock (caller forgot to inject one during integration) must surface as a
// decidable ErrNoClock — never a nil-pointer panic — and must not leave a
// half-baked entry in the attempt/risk-control book.
func TestVerifyID_NilClockReturnsErrNoClockNoDirtyCount(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register("alice", []byte("KINGXKINGXKINGXKINGX")); err != nil {
		t.Fatalf("register: %v", err)
	}
	v := NewVerifier(reg, Window{}, nil) // Clock intentionally not injected.

	// Many calls in a row must all short-circuit cleanly; none should panic and
	// none should be recorded as a genuine attempt.
	for i := 0; i < 5; i++ {
		err := v.VerifyID("alice", "000000")
		if !errors.Is(err, ErrNoClock) {
			t.Fatalf("call %d: want ErrNoClock, got %v", i, err)
		}
	}

	if got := v.AttemptCount("alice"); got != 0 {
		t.Fatalf("nil-clock calls must not count as attempts, got %d", got)
	}
}

// A real verify miss still records exactly one attempt, so the guard above
// doesn't silently swallow genuine failures.
func TestVerifyID_MissRecordsOneAttempt(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register("bob", []byte("KINGXKINGXKINGXKINGX")); err != nil {
		t.Fatalf("register: %v", err)
	}
	v := NewVerifier(reg, Window{}, clock.Fixed{})

	err := v.VerifyID("bob", "000000")
	if !errors.Is(err, ErrSkew) {
		t.Fatalf("want ErrSkew on miss, got %v", err)
	}
	if got := v.AttemptCount("bob"); got != 1 {
		t.Fatalf("genuine miss must record one attempt, got %d", got)
	}
}
