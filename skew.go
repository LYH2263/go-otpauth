package otpauth

import "fmt"

// SkewFail reports a clock-skew (out-of-window) verification failure.
//
// The returned error wraps ErrSkew with %w, so errors.Is(err, ErrSkew) holds
// reliably. This lets monitoring classify out-of-window failures by sentinel
// instead of scanning the message text for "skew". A non-nil cause is kept in
// the message for on-call diagnostics.
func SkewFail(cause error) error {
	if cause == nil {
		return fmt.Errorf("out of window: %w", ErrSkew)
	}
	return fmt.Errorf("%v: %w", cause, ErrSkew)
}
