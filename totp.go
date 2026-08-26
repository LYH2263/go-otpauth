package otpauth
import (
        "crypto/hmac"
        "crypto/sha1"
        "encoding/binary"
        "fmt"
        "math"
        "time"
)
func HOTP(secret []byte, counter uint64, digits int) string {
        if digits <= 0 { digits = 6 }
        var buf [8]byte
        binary.BigEndian.PutUint64(buf[:], counter)
        mac := hmac.New(sha1.New, secret)
        _, _ = mac.Write(buf[:])
        sum := mac.Sum(nil)
        off := sum[len(sum)-1] & 0x0f
        code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
        mod := uint32(math.Pow10(digits))
        return fmt.Sprintf("%0*d", digits, code%mod)
}
func TOTP(secret []byte, t time.Time, step int64, digits int) string {
        if step <= 0 { step = 30 }
        return HOTP(secret, uint64(t.Unix()/step), digits)
}
func VerifyTOTP(secret []byte, code string, t time.Time, step int64, digits, skew int) bool {
        if step <= 0 { step = 30 }
        ctr := t.Unix() / step
        for d := -skew; d <= skew; d++ {
                if HOTP(secret, uint64(ctr+int64(d)), digits) == code {
                        return true
                }
        }
        return false
}
