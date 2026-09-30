// Package rpid validates the RP IDs supported by the authenticator and its UI.
package rpid

import "errors"

const MaxSize = 253

// Validate accepts ASCII hostname characters, including punycode. It does not
// establish that a caller owns the domain or enforce DNS label syntax.
func Validate(id string) error {
	if len(id) == 0 || len(id) > MaxSize {
		return errors.New("invalid RP ID")
	}

	for _, c := range id {
		valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-'
		if !valid {
			return errors.New("RP ID must contain only ASCII hostname characters")
		}
	}

	return nil
}
