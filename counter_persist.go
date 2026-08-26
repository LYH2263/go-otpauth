package otpauth

import (
	"fmt"

	"github.com/LYH2263/go-otpauth/internal/persist"
)

func persistCounter(path, id string, n uint64) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}
	m := map[string]uint64{}
	_ = persist.LoadJSON(path, &m)
	m[id] = n
	return persist.SaveJSON(path, m)
}
