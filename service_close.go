package otpauth

func (b *BackupVault) CloseFlushCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0
	}
	// Capture the pending codes before clearing, so the close-time count
	// reflects the real number flushed rather than being wiped to 0 by Clear.
	flushed := append([]string(nil), b.codes...)
	b.codes = nil
	b.closed = true
	return len(flushed)
}
