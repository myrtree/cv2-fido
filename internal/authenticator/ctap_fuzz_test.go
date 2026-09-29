package authenticator

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// No real keys or disk writes: registration deliberately stops at the signer.
// Assertions return a dummy signature so response flags can still be checked.
type fuzzSigner struct {
	register func()
	sign     func()
}

func (s fuzzSigner) RegisterKey([]byte) ([]byte, *big.Int, *big.Int, error) {
	s.register()
	return nil, nil, nil, errors.New("fuzz signer does not create keys")
}

func (s fuzzSigner) SignASN1(_, _, _ []byte) ([]byte, error) {
	s.sign()
	return []byte("fuzz signature"), nil
}

func FuzzCTAPAuthorization(f *testing.F) {
	id := bytes.Repeat([]byte{0x42}, 32)
	f.Add(byte(4), []byte{}, false, false, false)
	f.Add(byte(2), []byte{0xa0}, false, false, false)
	f.Add(byte(2), []byte{0xa2, 1, 0x60, 1, 0x60}, false, false, false) // Duplicate keys.
	f.Add(byte(1), bytes.Repeat([]byte{0xff}, 7610), false, false, false)
	for _, probe := range []bool{false, true} {
		request := map[int]any{
			1: "example.com", 2: make([]byte, 32),
			3: []descriptor{{Type: "public-key", ID: id}},
			5: map[string]bool{"up": !probe, "uv": !probe},
		}
		data, err := cbor.Marshal(request)
		if err != nil {
			f.Fatal(err)
		}

		for _, deny := range []bool{false, true} {
			f.Add(byte(2), data, deny, false, false)
			f.Add(byte(2), data, deny, true, false)
			f.Add(byte(2), data, deny, false, true)
		}
	}

	request := registration()
	request[7] = map[string]bool{"rk": false}
	data, err := cbor.Marshal(request)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(byte(1), data, false, false, false)
	f.Add(byte(1), data, true, false, false)
	f.Fuzz(func(t *testing.T, cmd byte, data []byte, denyFingerprint, denySession, cancelled bool) {
		if len(data) > 2*maxMessage {
			return
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if cancelled {
			cancel()
		}

		// Decode independently of the production decoder to identify the only
		// request allowed to sign without a fingerprint: an explicit known-ID probe.
		var req assertionRequest
		probe := cmd == 2 && cbor.Unmarshal(data, &req) == nil &&
			req.Options != nil && !req.Options["uv"]
		up, explicit := req.Options["up"]
		probe = probe && explicit && !up && req.RP == "example.com" && len(req.Hash) == 32
		matched := false
		for _, d := range req.Allow {
			matched = matched || (d.Type == "public-key" && bytes.Equal(d.ID, id))
		}

		probe = probe && matched
		scans, signs, registrations := 0, 0, 0
		checkAuthorization := func(allowProbe bool) {
			needsFingerprint := !allowProbe || !probe
			if cancelled || denySession || (needsFingerprint && (denyFingerprint || scans != 1)) {
				t.Errorf("unauthorized key operation: cmd=%x probe=%t scans=%d", cmd, probe, scans)
			}
		}
		a := &Authenticator{
			notify: testNotify,
			store:  &store{credentials: []credential{{ID: id, RP: "example.com", User: []byte{1}, Key: []byte{1}, Resident: true}}},
			signer: fuzzSigner{
				register: func() { registrations++; checkAuthorization(false) },
				sign:     func() { signs++; checkAuthorization(true) },
			},
			verify: func(context.Context) error {
				scans++
				if denyFingerprint {
					return errors.New("fingerprint denied")
				}

				return nil
			},
			session: func(context.Context) (string, error) {
				if denySession {
					return "", errors.New("session denied")
				}

				return "fuzz-session", nil
			},
		}
		status, out := a.HandleCommand(ctx, cmd, data)
		if scans > 1 || signs > 1 || registrations > 1 || len(a.store.credentials) != 1 {
			t.Fatal("request repeated an operation or changed the credential store")
		}

		if (cancelled || (denySession && (cmd == 1 || cmd == 2))) && scans != 0 {
			t.Fatal("fingerprint requested after cancellation or session denial")
		}

		if status != 0 {
			if len(out) != 0 {
				t.Fatal("failed request leaked response data")
			}

			return
		}

		if cancelled || (cmd != 2 && cmd != 4) {
			t.Fatal("unexpected successful command")
		}

		if cmd == 2 {
			var response struct {
				Data []byte          `cbor:"2,keyasint"`
				User cbor.RawMessage `cbor:"4,keyasint"`
			}
			if err := cbor.Unmarshal(out, &response); err != nil || len(response.Data) != 37 || signs != 1 {
				t.Fatal("invalid assertion response", err)
			}

			if probe {
				if scans != 0 || response.Data[32] != 0 || len(response.User) != 0 {
					t.Fatal("silent probe exposed user data or claimed presence/verification")
				}
			} else if scans != 1 || denyFingerprint || response.Data[32] != 0x05 {
				t.Fatal("assertion succeeded without fresh user verification")
			}
		}
	})
}
