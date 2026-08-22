package otpauth
import (
        "encoding/base32"
        "fmt"
        "net/url"
)
func OTPAuthURI(issuer, account string, secret []byte, digits int, step int64) string {
        if digits <= 0 { digits = 6 }
        if step <= 0 { step = 30 }
        label := url.PathEscape(issuer + ":" + account)
        v := url.Values{}
        v.Set("secret", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret))
        v.Set("issuer", issuer)
        v.Set("digits", fmt.Sprintf("%d", digits))
        v.Set("period", fmt.Sprintf("%d", step))
        return "otpauth://totp/" + label + "?" + v.Encode()
}
