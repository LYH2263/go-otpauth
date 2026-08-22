package otpauth

import "fmt"

func SkewFail(err error) error {
	if err == nil {
		return fmt.Errorf("window")
	}
	return fmt.Errorf("skew: %v", err)
}
