package otpauth

import "errors"

var (
	ErrClosed   = errors.New("otpauth: closed")
	ErrInvalid  = errors.New("otpauth: invalid")
	ErrNotFound = errors.New("otpauth: not found")
	ErrConflict = errors.New("otpauth: conflict")
	ErrSkew     = errors.New("otpauth: skew")
	ErrNoClock  = errors.New("otpauth: no clock")
)
