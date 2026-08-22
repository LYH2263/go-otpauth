package otpauth

import (
	"encoding/hex"
	"testing"
	"time"
)

// TestRegisterDecouplesFromCallerBuffer reproduces the reported MFA failure:
// after Register the caller mutates the same secret buffer (here simulating a
// "debug hex" reuse) and the stored key must not change, otherwise the whole
// batch of TOTP verifications would fail.
func TestRegisterDecouplesFromCallerBuffer(t *testing.T) {
	reg := NewRegistry()
	defer reg.Close()

	_, secret, err := RandomSecret(20)
	if err != nil {
		t.Fatalf("RandomSecret: %v", err)
	}
	id := "user-1"
	if err := reg.Register(id, secret); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Caller reuses the very same buffer for a debug hex dump and scribbles
	// all over it.
	_ = hex.Dump(secret)
	for i := range secret {
		secret[i] = 0xFF
	}

	got, err := reg.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if equalSlice(got, secret) {
		t.Fatalf("stored secret aliases caller buffer: got %x, still equal to mutated buffer %x", got, secret)
	}

	// The real symptom: a freshly generated code for the ORIGINAL secret must
	// still verify.
	now := time.Now()
	want := TOTP(got, now, 30, 6)
	win := Window{Step: 30, Digits: 6, Skew: 1}
	if !win.Verify(got, want, now) {
		t.Fatalf("TOTP no longer verifies after caller mutated its buffer; want %s", want)
	}
}

// TestSnapshotSecretsIsDefensiveCopy ensures the snapshot neither aliases the
// internal map nor its byte slices: mutating the returned value must not
// affect subsequent Get calls.
func TestSnapshotSecretsIsDefensiveCopy(t *testing.T) {
	reg := NewRegistry()
	defer reg.Close()

	_, secret, err := RandomSecret(20)
	if err != nil {
		t.Fatalf("RandomSecret: %v", err)
	}
	id := "user-2"
	if err := reg.Register(id, secret); err != nil {
		t.Fatalf("Register: %v", err)
	}

	snap := reg.SnapshotSecrets()
	// Mutate the snapshot's slice and map in every way a careless caller can.
	if bs, ok := snap[id]; ok {
		for i := range bs {
			bs[i] = 0x00
		}
	}
	delete(snap, id)
	snap["bogus"] = []byte{0x42}

	got, err := reg.Get(id)
	if err != nil {
		t.Fatalf("Get after snapshot mutation: %v", err)
	}
	if !equalSlice(got, secret) {
		t.Fatalf("snapshot mutation leaked into registry: got %x, want original %x", got, secret)
	}
}

func equalSlice(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
