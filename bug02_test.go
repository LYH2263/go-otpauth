package otpauth_test

import (
	"testing"

	otpauth "github.com/LYH2263/go-otpauth"
)

func TestBug02_SnapshotSecretsIsolated(t *testing.T) {
	r := otpauth.NewRegistry()
	defer r.Close()
	sec := []byte("0123456789abcdef0123")
	if err := r.Register("a", sec); err != nil {
		t.Fatal(err)
	}
	snap := r.SnapshotSecrets()
	snap["a"][0] ^= 0xff
	got, err := r.Get("a")
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != sec[0] {
		t.Fatalf("polluted %v vs %v", got[0], sec[0])
	}
}
