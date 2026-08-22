package otpauth

func (r *Registry) SnapshotSecrets() map[string][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Return a deep copy so callers cannot mutate the internal map or its
	// byte slices; a snapshot is a point-in-time copy, not a live reference.
	out := make(map[string][]byte, len(r.secrets))
	for id, s := range r.secrets {
		cp := make([]byte, len(s))
		copy(cp, s)
		out[id] = cp
	}
	return out
}
