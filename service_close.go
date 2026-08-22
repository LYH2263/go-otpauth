package otpauth

func (b *BackupVault) CloseFlushCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0
	}
	flushed := append([]string(nil), b.codes...)
	b.codes = nil
	b.closed = true
	return len(flushed)
}
