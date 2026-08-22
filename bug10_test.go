package otpauth_test

import (
	"testing"

	otpauth "github.com/LYH2263/go-otpauth"
)

func TestBug10_CloseFlushesBackupFirst(t *testing.T) {
	b := otpauth.NewBackupVault([]string{"c1", "c2", "c3"})
	if b.CloseFlushCount() == 0 {
		t.Fatal("want flush")
	}
}
