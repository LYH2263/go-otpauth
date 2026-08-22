package otpauth

import "sync"

type BackupVault struct {
	mu     sync.Mutex
	codes  []string
	closed bool
}

func NewBackupVault(codes []string) *BackupVault {
	cp := append([]string(nil), codes...)
	return &BackupVault{codes: cp}
}

func (b *BackupVault) Pending() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.codes)
}

func (b *BackupVault) Flush() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := append([]string(nil), b.codes...)
	return out
}

func (b *BackupVault) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.codes = nil
}
