package otpauth_test

import (
	"errors"
	"testing"

	otpauth "github.com/LYH2263/go-otpauth"
)

func TestBug04_NilClockNoDirtyAttempt(t *testing.T) {
	r := otpauth.NewRegistry()
	defer r.Close()
	_ = r.Register("a", []byte("0123456789abcdef0123"))
	v := otpauth.NewVerifier(r, otpauth.Window{Step: 30, Digits: 6, Skew: 1}, nil)
	var panicked bool
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		err := v.VerifyID("a", "000000")
		if panicked {
			return
		}
		if err == nil || !errors.Is(err, otpauth.ErrNoClock) {
			t.Fatalf("%v", err)
		}
	}()
	if panicked {
		t.Fatal("panic")
	}
	if v.AttemptCount("a") != 0 {
		t.Fatalf("dirty attempts %d", v.AttemptCount("a"))
	}
}
