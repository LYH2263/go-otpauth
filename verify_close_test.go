package otpauth

import (
	"errors"
	"testing"
	"time"

	"github.com/LYH2263/go-otpauth/internal/clock"
)

func TestVerifyIDClosedReturnsErrClosed(t *testing.T) {
	reg := NewRegistry()
	id, sec, err := RandomSecret(20)
	if err != nil {
		t.Fatalf("RandomSecret: %v", err)
	}
	if err := reg.Register(id, sec); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// valid code before close, checked at the same instant the code was minted
	now := time.Unix(1000, 0)
	code := TOTP(sec, now, 30, 6)
	v := NewVerifier(reg, Window{}, clock.Fixed{T: now})
	if err := v.VerifyID(id, code); err != nil {
		t.Fatalf("verify before close: %v", err)
	}
	// close for hot-swap; in-flight must see ErrClosed, not ErrNotFound/panic
	reg.Close()
	err = v.VerifyID(id, code)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("after close: want ErrClosed, got %v", err)
	}
	// Get directly also ErrClosed
	if _, err := reg.Get(id); !errors.Is(err, ErrClosed) {
		t.Fatalf("Get after close: want ErrClosed, got %v", err)
	}
	// Register after close is ErrClosed
	if err := reg.Register("x", []byte{1, 2}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Register after close: want ErrClosed, got %v", err)
	}
}

func TestVerifyIDNotFoundBeforeClosed(t *testing.T) {
	reg := NewRegistry()
	v := NewVerifier(reg, Window{}, clock.Fixed{T: time.Unix(1000, 0)})
	// open registry must still report ErrNotFound for a missing id,
	// never accidentally ErrClosed
	if err := v.VerifyID("missing", "123456"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing id: want ErrNotFound, got %v", err)
	}
}
