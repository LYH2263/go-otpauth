package otpauth

import "context"

type Pair struct {
	ID   string
	Code string
}

func BulkVerify(ctx context.Context, v *Verifier, pairs []Pair) error {
	for _, p := range pairs {
		// Honor the caller's deadline/cancellation so a bulk import stops
		// promptly when the client gives up, instead of grinding through
		// the whole batch (which pegs CPU and stalls the import queue).
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := runVerify(ctx, v, p.ID, p.Code); err != nil {
			return err
		}
	}
	return nil
}
