package otpauth
import "time"
type Window struct {
        Step int64
        Digits int
        Skew int
}
func (w Window) withDefaults() Window {
        if w.Step <= 0 { w.Step = 30 }
        if w.Digits <= 0 { w.Digits = 6 }
        if w.Skew < 0 { w.Skew = 1 }
        return w
}
func (w Window) Verify(secret []byte, code string, t time.Time) bool {
        w = w.withDefaults()
        return VerifyTOTP(secret, code, t, w.Step, w.Digits, w.Skew)
}
