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
	// Guard the missing-clock wiring error before any side effect: a nil Clock
	// is a caller misconfiguration, not a genuine verify attempt, so it must
	// not leave a half-baked entry in the attempt/risk-control book.
	if v.Clock == nil {
		return ErrNoClock
	}
	sec, err := v.Reg.Get(id)
	if err != nil {
		return err
	}
	if v.Attempts != nil {
		v.Attempts.Note(id)
	}
	t := v.Clock.Now()
	if v.Win.Verify(sec, code, t) {
		return nil
	}
	return SkewFail(fmt.Errorf("code miss at %s", t.UTC().Format(time.RFC3339)))
}
