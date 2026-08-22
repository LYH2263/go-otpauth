package otpauth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConsumeRollsBackMemoryOnPersistError(t *testing.T) {
	dir := t.TempDir()
	// "blocker" is a regular file, so a counter path beneath it cannot be
	// created: persistCounter -> SaveJSON -> MkdirAll fails and nothing is
	// written. This mirrors the production incident where the persistence
	// path was made read-only under load.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("create blocker: %v", err)
	}
	path := filepath.Join(blocker, "counter.json")
	c := NewCounterStore(path)

	// Repeated failed persists must not advance the in-memory counter. If
	// they did, each failure would silently burn a password slot and the
	// window would drift after the next restart.
	for i := 0; i < 3; i++ {
		if _, err := c.Consume("user"); err == nil {
			t.Fatalf("iter %d: expected persist error, got nil", i)
		}
		if got := c.Get("user"); got != 0 {
			t.Fatalf("iter %d: in-memory counter = %d after failed persist; must stay 0 so a retry does not skip a password", i, got)
		}
	}

	// Repair the path so persist can succeed, using the SAME store. The next
	// Consume must return 1 — not 4 — proving no counter was consumed off-book
	// while persistence was failing.
	if err := os.Remove(blocker); err != nil {
		t.Fatalf("remove blocker: %v", err)
	}
	if err := os.Mkdir(blocker, 0o755); err != nil {
		t.Fatalf("mkdir blocker: %v", err)
	}
	n, err := c.Consume("user")
	if err != nil {
		t.Fatalf("healthy persist: %v", err)
	}
	if n != 1 {
		t.Fatalf("healthy persist: expected counter 1, got %d (a failed persist secretly advanced the counter)", n)
	}
}
