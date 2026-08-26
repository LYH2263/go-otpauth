package otpauth

import "github.com/LYH2263/go-otpauth/internal/clone"

// SnapshotSecrets returns deep copies of registered secrets for admin export.
func (r *Registry) SnapshotSecrets() map[string][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string][]byte, len(r.secrets))
	for id, s := range r.secrets {
		out[id] = clone.Bytes(s)
	}
	return out
}
