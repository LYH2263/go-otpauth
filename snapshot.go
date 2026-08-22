package otpauth

func (r *Registry) SnapshotSecrets() map[string][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string][]byte, len(r.secrets))
	for id, s := range r.secrets {
		out[id] = s
	}
	return out
}
