package otpauth_test

import (
	"errors"
	"testing"
	"time"

	otpauth "github.com/LYH2263/go-otpauth"
	"github.com/LYH2263/go-otpauth/internal/clock"
)

func TestBug03_VerifyAfterClose(t *testing.T) {
	r := otpauth.NewRegistry()
	_ = r.Register("a", []byte("0123456789abcdef0123"))
	v := otpauth.NewVerifier(r, otpauth.Window{Step: 30, Digits: 6, Skew: 1}, clock.Fixed{T: time.Unix(1_700_000_000, 0)})
	r.Close()
	var panicked bool
	var err error
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		err = v.VerifyID("a", "000000")
	}()
	if panicked {
		t.Fatal("panic")
	}
	if !errors.Is(err, otpauth.ErrClosed) {
		t.Fatalf("%v", err)
	}
}
