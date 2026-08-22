package otpauth_test

import (
	"bytes"
	"testing"

	otpauth "github.com/LYH2263/go-otpauth"
)

func TestBug01_RegisterIsolatesSecret(t *testing.T) {
	r := otpauth.NewRegistry()
	defer r.Close()
	buf := []byte("0123456789abcdef0123")
	if err := r.Register("a", buf); err != nil {
		t.Fatal(err)
	}
	buf[0] = 'Z'
	got, err := r.Get("a")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, buf) {
		t.Fatalf("register leaked %q", got)
	}
	snap := r.SnapshotSecrets()
	snap["a"][0] = 'Q'
	got2, _ := r.Get("a")
	if got2[0] == 'Q' {
		t.Fatal("snapshot leaked")
	}
}
