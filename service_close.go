package otpauth

func (b *BackupVault) CloseFlushCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0
	}
	b.codes = nil
	flushed := append([]string(nil), b.codes...)
	b.closed = true
	return len(flushed)
}
