package otpauth_test

import (
	"context"
	"testing"
	"time"

	otpauth "github.com/LYH2263/go-otpauth"
	"github.com/LYH2263/go-otpauth/internal/clock"
)

func TestBug08_BulkVerifyHonorsCancel(t *testing.T) {
	r := otpauth.NewRegistry()
	defer r.Close()
	sec := []byte("0123456789abcdef0123")
	_ = r.Register("a", sec)
	fixed := time.Unix(1_700_000_000, 0)
	v := otpauth.NewVerifier(r, otpauth.Window{Step: 30, Digits: 6, Skew: 1}, clock.Fixed{T: fixed})
	code := otpauth.TOTP(sec, fixed, 30, 6)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pairs := make([]otpauth.Pair, 50)
	for i := range pairs {
		pairs[i] = otpauth.Pair{ID: "a", Code: code}
	}
	if err := otpauth.BulkVerify(ctx, v, pairs); err == nil {
		t.Fatal("want cancel")
	}
}
