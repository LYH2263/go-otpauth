package otpauth

import "testing"

// SnapshotSecrets must return a deep copy: redacting a secret inside the
// exported map (the security-team display-masking use case) must not dirty the
// live secret table that Get/Verify read in-process.
func TestSnapshotSecretsIsolation(t *testing.T) {
	Reg := NewRegistry()

	secret := []byte("S3CR3T-PLAINTEXT")
	if err := Reg.Register("acct", secret); err != nil {
		t.Fatal(err)
	}

	// Export a snapshot for redacted display.
	snap := Reg.SnapshotSecrets()

	// Security masks the displayed value in place, as described in the report.
	if s, ok := snap["acct"]; ok && len(s) > 0 {
		for i := range s {
			s[i] = '*'
		}
	}

	// The live table must be untouched: Get returns the original bytes and
	// Verify (which calls Get) would otherwise fail on a valid code.
	got, err := Reg.Get("acct")
	if err != nil {
		t.Fatalf("Get after snapshot redaction: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatalf("live secret dirtied by snapshot: got %q want %q", got, secret)
	}

	// The snapshot itself should reflect the caller's masking, proving we did
	// not accidentally hand back the live backing array either way. We only
	// check that it no longer equals the original and is all stars.
	masked := snap["acct"]
	if string(masked) == string(secret) {
		t.Fatalf("snapshot equals original secret; backing array shared")
	}
	for i, b := range masked {
		if b != '*' {
			t.Fatalf("snapshot byte %d is %q, want '*'", i, b)
		}
	}
}
