package tpm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/google/go-tpm/tpm2"
	"testing"
)

// Captured from the original backend before refactoring, using synthetic input.
func TestTemplateCompatibility(t *testing.T) {
	rp := sha256.Sum256([]byte("example.com"))
	for _, tt := range []struct {
		name     string
		template tpm2.Public
		want     string
	}{
		{"primary", primaryKeyTmpl(bytes.Repeat([]byte{0x42}, 20), rp[:]), "0023000b0003007200000006008000430010000300100020197cadc6569bd77b3d660b56c8afad722f0976b046688928675a86972f9a49d900206be4f5c7b381b7d1059c39c299b40a17a9789d2465cb0c1839b667cd5a3aee31"},
		{"child", signingKeyTemplate(), "0023000b00040072000000100018000b000300100020000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.template.Encode()
			if err != nil {
				t.Fatal(err)
			}

			if hex.EncodeToString(got) != tt.want {
				t.Fatalf("TPM template changed: %x", got)
			}
		})
	}
}
