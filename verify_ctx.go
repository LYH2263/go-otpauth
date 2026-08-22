package otpauth

import "context"

func runVerify(ctx context.Context, v *Verifier, id, code string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return v.VerifyID(id, code)
}

func (v *Verifier) VerifyContext(ctx context.Context, id, code string) error {
	return runVerify(ctx, v, id, code)
}
