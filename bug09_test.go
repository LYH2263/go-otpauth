package otpauth_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/LYH2263/go-otpauth/internal/audit"
)

func TestBug09_RotateClosesOldAudit(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "a.log")
	p2 := filepath.Join(dir, "b.log")
	l, err := audit.Open(p1)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Log("x", "1"); err != nil {
		t.Fatal(err)
	}
	if err := l.Rotate(p2); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p1); err != nil {
		t.Fatalf("locked %v", err)
	}
}
