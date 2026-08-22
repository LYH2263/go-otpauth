package otpauth

import "fmt"

// SkewFail wraps a verification miss as ErrSkew for callers using errors.Is.
func SkewFail(err error) error {
	if err == nil {
		return fmt.Errorf("%w: window", ErrSkew)
	}
	return fmt.Errorf("%w: %v", ErrSkew, err)
}
