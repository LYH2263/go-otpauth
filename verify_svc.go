package otpauth

import (
	"fmt"
	"time"

	"github.com/LYH2263/go-otpauth/internal/clock"
)

type Verifier struct {
	Reg      *Registry
	Win      Window
	Clock    clock.Clock
	Attempts *AttemptBook
}

func NewVerifier(reg *Registry, win Window, clk clock.Clock) *Verifier {
	return &Verifier{Reg: reg, Win: win, Clock: clk, Attempts: NewAttemptBook()}
}

func (v *Verifier) AttemptCount(id string) int {
	if v.Attempts == nil {
		return 0
	}
	return v.Attempts.Count(id)
}

func (v *Verifier) VerifyID(id, code string) error {
	if v.Clock == nil {
		return ErrNoClock
	}
	// Go through Get so a closed registry surfaces as ErrClosed for any
	// in-flight verification during hot-swap, instead of a nil-map read or
	// an ErrNotFound masquerading as closed.
	s, err := v.Reg.Get(id)
	if err != nil {
		return err
	}
	sec := append([]byte(nil), s...)
	if v.Attempts != nil {
		v.Attempts.Note(id)
	}
	t := v.Clock.Now()
	if v.Win.Verify(sec, code, t) {
		return nil
	}
	return SkewFail(fmt.Errorf("code miss at %s", t.UTC().Format(time.RFC3339)))
}
