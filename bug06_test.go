package otpauth_test

import (
	"os"
	"path/filepath"
	"testing"

	otpauth "github.com/LYH2263/go-otpauth"
)

func TestBug06_CounterPersistRollback(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "counter.json")
	if err := os.Mkdir(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	c := otpauth.NewCounterStore(badPath)
	before := c.Get("u1")
	if _, err := c.Consume("u1"); err == nil {
		t.Fatal("want persist fail")
	}
	if c.Get("u1") != before {
		t.Fatalf("counter drifted %d -> %d", before, c.Get("u1"))
	}
}
