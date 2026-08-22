package otpauth

import "context"

func runVerify(ctx context.Context, v *Verifier, id, code string) error {
	// Honor caller cancellation before doing any verify work; a canceled
	// ctx must short-circuit instead of running to completion and emitting
	// a phantom success.
	if err := ctx.Err(); err != nil {
		return err
	}
	return v.VerifyID(id, code)
}

func (v *Verifier) VerifyContext(ctx context.Context, id, code string) error {
	return runVerify(ctx, v, id, code)
}
