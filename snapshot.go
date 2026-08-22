package otpauth

// SnapshotSecrets returns a read-only view of the registry's secrets.
// The returned map and its []byte values are deep copies: callers may
// mask or otherwise mutate the export (e.g. redacting secrets to '*'
// for display) without affecting the live secret table. This isolation
// matters because Get/Verify read the same table in-process — sharing
// backing storage would let a display-side redaction dirty the secret
// used for verification, making a valid code fail.
func (r *Registry) SnapshotSecrets() map[string][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string][]byte, len(r.secrets))
	for id, s := range r.secrets {
		cp := make([]byte, len(s))
		copy(cp, s)
		out[id] = cp
	}
	return out
}
