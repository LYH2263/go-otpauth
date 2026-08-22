package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRotateReleasesOldHandle reproduces the Windows "sharing violation"
// symptom: after Rotate, the old audit file must be deletable while the
// logger keeps running against the new path. The previous Rotate leaked the
// old *os.File handle, holding a sharing lock on the file and blocking the
// compliance archive step from clearing it.
func TestRotateReleasesOldHandle(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "audit.log")
	newPath := filepath.Join(dir, "audit.log.1")

	l, err := Open(oldPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if err := l.Log("put", "a"); err != nil {
		t.Fatalf("Log: %v", err)
	}

	if err := l.Rotate(newPath); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// The new path must be the live one.
	if err := l.Log("put", "b"); err != nil {
		t.Fatalf("Log after rotate: %v", err)
	}

	// The old audit file must be removable on Windows — a leaked handle
	// would keep a sharing lock and this Remove would fail with a sharing
	// violation. This is the exact symptom the compliance archive hit.
	if err := os.Remove(oldPath); err != nil {
		t.Fatalf("old audit file still locked after Rotate: %v", err)
	}

	// Logger must remain usable against the new path.
	if err := l.Log("put", "c"); err != nil {
		t.Fatalf("Log after remove: %v", err)
	}
}

// TestRotateKeepsOldHandleOnFailure guards the no-op-on-failure contract:
// when opening the new path fails, the logger must keep writing to the old
// path instead of being left with no handle at all.
func TestRotateKeepsOldHandleOnFailure(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "audit.log")
	// A path whose directory does not exist — OpenFile must fail.
	badPath := filepath.Join(dir, "nope", "audit.log.1")

	l, err := Open(oldPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if err := l.Log("put", "a"); err != nil {
		t.Fatalf("Log: %v", err)
	}

	if err := l.Rotate(badPath); err == nil {
		t.Fatalf("Rotate: expected error, got nil")
	}

	// Must still be live on the old path.
	if err := l.Log("put", "b"); err != nil {
		t.Fatalf("Log after failed rotate: %v", err)
	}

	if l.path != oldPath {
		t.Fatalf("path changed on failed rotate: got %q want %q", l.path, oldPath)
	}
}
