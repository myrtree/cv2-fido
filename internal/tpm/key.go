package tpm

import (
	"errors"
	"math"
)

const (
	wrappedKeyMagic      = "TPM"
	wrappedKeyHeaderSize = len(wrappedKeyMagic) + 1
)

type wrappedKey struct {
	private, public, seed []byte
}

var errInvalidKey = errors.New("invalid TPM credential encoding")

// Preserve tpm-fido's format: three "TPM" + uint8 length + payload records.
func encodeKey(k wrappedKey) ([]byte, error) {
	if len(k.seed) != seedSizeBytes {
		return nil, errInvalidKey
	}

	var out []byte
	for _, part := range [][]byte{k.private, k.public, k.seed} {
		if len(part) == 0 || len(part) > math.MaxUint8 {
			return nil, errInvalidKey
		}

		out = append(out, wrappedKeyMagic...)
		out = append(out, byte(len(part)))
		out = append(out, part...)
	}

	return out, nil
}

// Returned slices reference data and are read-only for the duration of signing.
func decodeKey(data []byte) (wrappedKey, error) {
	var k wrappedKey
	for _, part := range []*[]byte{&k.private, &k.public, &k.seed} {
		if len(data) < wrappedKeyHeaderSize || string(data[:len(wrappedKeyMagic)]) != wrappedKeyMagic {
			return wrappedKey{}, errInvalidKey
		}

		n := int(data[len(wrappedKeyMagic)])
		data = data[wrappedKeyHeaderSize:]
		if n == 0 || n > len(data) {
			return wrappedKey{}, errInvalidKey
		}

		*part = data[:n:n]
		data = data[n:]
	}

	if len(data) != 0 || len(k.seed) != seedSizeBytes {
		return wrappedKey{}, errInvalidKey
	}

	return k, nil
}
