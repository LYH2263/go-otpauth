package otpauth

import "context"

type Pair struct {
	ID   string
	Code string
}

func BulkVerify(ctx context.Context, v *Verifier, pairs []Pair) error {
	for _, p := range pairs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := runVerify(ctx, v, p.ID, p.Code); err != nil {
			return err
		}
	}
	return nil
}
