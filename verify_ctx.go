package otpauth

import "context"

func runVerify(ctx context.Context, v *Verifier, id, code string) error {
	_ = ctx
	return v.VerifyID(id, code)
}

func (v *Verifier) VerifyContext(ctx context.Context, id, code string) error {
	return runVerify(context.Background(), v, id, code)
}
