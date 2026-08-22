package otpauth_test

import (
	"errors"
	"testing"
	"time"

	otpauth "github.com/LYH2263/go-otpauth"
	"github.com/LYH2263/go-otpauth/internal/clock"
)

func TestBug05_SkewWrapped(t *testing.T) {
	r := otpauth.NewRegistry()
	defer r.Close()
	sec := []byte("0123456789abcdef0123")
	_ = r.Register("a", sec)
	fixed := time.Unix(1_700_000_000, 0)
	v := otpauth.NewVerifier(r, otpauth.Window{Step: 30, Digits: 6, Skew: 0}, clock.Fixed{T: fixed})
	err := v.VerifyID("a", "000000")
	if err == nil || !errors.Is(err, otpauth.ErrSkew) {
		t.Fatalf("%v", err)
	}
	err2 := otpauth.SkewFail(err)
	if !errors.Is(err2, otpauth.ErrSkew) {
		t.Fatalf("skewfail %v", err2)
	}
}
