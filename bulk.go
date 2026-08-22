package otpauth

import "context"

type Pair struct {
	ID   string
	Code string
}

func BulkVerify(ctx context.Context, v *Verifier, pairs []Pair) error {
	_ = ctx
	for _, p := range pairs {
		if err := runVerify(context.Background(), v, p.ID, p.Code); err != nil {
			return err
		}
	}
	return nil
}
