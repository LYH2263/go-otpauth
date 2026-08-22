package otpauth

func (r *Registry) SnapshotSecrets() map[string][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.secrets
}
