package otpauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/LYH2263/go-otpauth/internal/clock"
)

// fixedStep returns a clock pinned to a Unix step boundary, so TOTP codes are
// stable and deterministic across the test.
func fixedStep(unix int64) clock.Fixed {
	return clock.Fixed{T: time.Unix(unix, 0).UTC()}
}

// TestSkewFailWrapsErrSkew guards the monitoring contract: an out-of-window
// failure must be identifiable via errors.Is(err, ErrSkew), not by scraping
// the error message text.
func TestSkewFailWrapsErrSkew(t *testing.T) {
	// With a cause.
	err := SkewFail(errors.New("code miss at 2026-08-22T00:00:00Z"))
	if !errors.Is(err, ErrSkew) {
		t.Fatalf("errors.Is(err, ErrSkew) = false; want true (err=%v)", err)
	}

	// Without a cause (nil).
	errNil := SkewFail(nil)
	if !errors.Is(errNil, ErrSkew) {
		t.Fatalf("errors.Is(nil-cause err, ErrSkew) = false; want true (err=%v)", errNil)
	}
}

// TestVerifyID_OutOfWindowReturnsErrSkew drives the real verify path: a code
// outside the skew window must surface as ErrSkew so monitoring can classify
// it as a skew failure rather than a generic error string.
func TestVerifyID_OutOfWindowReturnsErrSkew(t *testing.T) {
	sec := []byte("window-skew-regression-secret")
	// HOTP at a counter of 0 is far outside any live TOTP step, so it is a
	// guaranteed out-of-window code (barring astronomically unlikely collision).
	wrong := HOTP(sec, 0, 6)
	if wrong == "" {
		t.Fatalf("HOTP produced empty code")
	}

	reg := NewRegistry()
	if err := reg.Register("user", sec); err != nil {
		t.Fatalf("register: %v", err)
	}

	v := NewVerifier(reg, Window{Step: 30, Digits: 6, Skew: 1}, fixedStep(1_700_000_000))

	err := v.VerifyID("user", wrong)
	if !errors.Is(err, ErrSkew) {
		t.Fatalf("errors.Is(verify err, ErrSkew) = false; want true (err=%v)", err)
	}
}

// TestVerifyID_ValidCodeNoSkew ensures a correct code is accepted and does not
// carry ErrSkew — confirming the skew wrapping is failure-only.
func TestVerifyID_ValidCodeNoSkew(t *testing.T) {
	sec := []byte("window-skew-valid-secret")
	const nowUnix = 1_700_000_000
	reg := NewRegistry()
	if err := reg.Register("u", sec); err != nil {
		t.Fatalf("register: %v", err)
	}
	v := NewVerifier(reg, Window{Step: 30, Digits: 6, Skew: 1}, fixedStep(nowUnix))

	good := TOTP(sec, time.Unix(nowUnix, 0).UTC(), 30, 6)
	if err := v.VerifyID("u", good); err != nil {
		t.Fatalf("expected nil for valid code, got %v", err)
	}
}

// TestBulkVerify_PropagatesErrSkew checks the batch path also preserves the
// sentinel through runVerify so downstream alerts classify each failure.
func TestBulkVerify_PropagatesErrSkew(t *testing.T) {
	sec := []byte("bulk-skew-secret")
	reg := NewRegistry()
	if err := reg.Register("b", sec); err != nil {
		t.Fatalf("register: %v", err)
	}
	v := NewVerifier(reg, Window{Step: 30, Digits: 6, Skew: 1}, fixedStep(1_700_000_000))

	// A counter very far from any live step -> guaranteed out-of-window.
	wrong := HOTP(sec, 1<<40, 6)
	err := BulkVerify(context.Background(), v, []Pair{{ID: "b", Code: wrong}})
	if !errors.Is(err, ErrSkew) {
		t.Fatalf("errors.Is(bulk err, ErrSkew) = false; want true (err=%v)", err)
	}
}
