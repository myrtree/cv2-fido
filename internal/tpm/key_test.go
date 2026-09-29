package tpm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Synthetic fixture in the original format; not a real TPM credential.
const legacyKeyHex = "54504d0301020354504d02040554504d14000102030405060708090a0b0c0d0e0f10111213"

func TestKeyCodecCompatibility(t *testing.T) {
	fixture, err := hex.DecodeString(legacyKeyHex)
	if err != nil {
		t.Fatal(err)
	}

	k, err := decodeKey(fixture)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(k.private, []byte{1, 2, 3}) || !bytes.Equal(k.public, []byte{4, 5}) || len(k.seed) != 20 {
		t.Fatal("wrong record order or contents")
	}

	encoded, err := encodeKey(k)
	if err != nil || !bytes.Equal(encoded, fixture) {
		t.Fatalf("wire format changed: %x, %v", encoded, err)
	}

	for _, size := range []int{1, 255} {
		k := wrappedKey{bytes.Repeat([]byte{1}, size), bytes.Repeat([]byte{2}, size), bytes.Repeat([]byte{3}, 20)}
		// Original wire layout, previously checked against the legacy encoder.
		old := bytes.Join([][]byte{
			{'T', 'P', 'M', byte(size)}, k.private,
			{'T', 'P', 'M', byte(size)}, k.public,
			{'T', 'P', 'M', 20}, k.seed,
		}, nil)
		got, err := encodeKey(k)
		if err != nil || !bytes.Equal(got, old) {
			t.Fatal("incompatible with old encoder", err)
		}

		decoded, err := decodeKey(old)
		if err != nil || !bytes.Equal(decoded.private, k.private) || !bytes.Equal(decoded.public, k.public) || !bytes.Equal(decoded.seed, k.seed) {
			t.Fatal("incompatible with old data", err)
		}
	}
}

func TestKeyCodecRejectsMalformedData(t *testing.T) {
	fixture, _ := hex.DecodeString(legacyKeyHex)
	for n := 0; n < len(fixture); n++ {
		if _, err := decodeKey(fixture[:n]); err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}

	for _, index := range []int{0, 7, 13} {
		bad := bytes.Clone(fixture)
		bad[index] = 'X'
		if _, err := decodeKey(bad); err == nil {
			t.Fatal("accepted wrong separator")
		}
	}

	for _, suffix := range [][]byte{{0}, []byte("TPM"), []byte("TPM\x01x")} {
		if _, err := decodeKey(append(bytes.Clone(fixture), suffix...)); err == nil {
			t.Fatal("accepted trailing data")
		}
	}

	for _, sizes := range [][3]int{{0, 1, 20}, {1, 0, 20}, {256, 1, 20}, {1, 256, 20}, {1, 1, 0}, {1, 1, 19}, {1, 1, 21}} {
		k := wrappedKey{make([]byte, sizes[0]), make([]byte, sizes[1]), make([]byte, sizes[2])}
		if _, err := encodeKey(k); err == nil {
			t.Fatalf("accepted lengths %v", sizes)
		}

		if sizes[0] <= 255 && sizes[1] <= 255 {
			bad := bytes.Join([][]byte{
				{'T', 'P', 'M', byte(sizes[0])}, k.private,
				{'T', 'P', 'M', byte(sizes[1])}, k.public,
				{'T', 'P', 'M', byte(sizes[2])}, k.seed,
			}, nil)
			if _, err := decodeKey(bad); err == nil {
				t.Fatalf("decoded invalid lengths %v", sizes)
			}
		}
	}
}

func FuzzDecodeKey(f *testing.F) {
	fixture, _ := hex.DecodeString(legacyKeyHex)
	f.Add(fixture)
	f.Add([]byte{})
	f.Add([]byte("TPM\xff"))
	f.Fuzz(func(t *testing.T, data []byte) {
		k, err := decodeKey(data)
		if err != nil {
			return
		}

		encoded, err := encodeKey(k)
		if err != nil || !bytes.Equal(encoded, data) {
			t.Fatal("accepted noncanonical key")
		}
	})
}
