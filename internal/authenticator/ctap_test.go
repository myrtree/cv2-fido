package authenticator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type testSigner struct {
	keys  map[string]*ecdsa.PrivateKey
	rps   map[string]string
	signs int
}

func (s *testSigner) RegisterKey(rp []byte) ([]byte, *big.Int, *big.Int, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	id := make([]byte, 32)
	rand.Read(id)
	s.keys[string(id)] = k
	s.rps[string(id)] = string(rp)
	return id, k.X, k.Y, nil
}
func (s *testSigner) SignASN1(id, rp, digest []byte) ([]byte, error) {
	s.signs++
	k := s.keys[string(id)]
	if k == nil || s.rps[string(id)] != string(rp) {
		return nil, errors.New("wrong key or RP")
	}

	return ecdsa.SignASN1(rand.Reader, k, digest)
}
func testAuthenticator(t *testing.T) (*Authenticator, *testSigner, *int) {
	t.Helper()
	s, err := openStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = s.Close() })
	signer := &testSigner{keys: make(map[string]*ecdsa.PrivateKey), rps: make(map[string]string)}
	checks := new(int)
	a := &Authenticator{
		logger: log.Default(),
		notify: testNotify,
		store:  s, signer: signer, verify: func(context.Context) error { *checks++; return nil },
		session: func(context.Context) (string, error) { return "test-session", nil },
	}
	// Protocol tests advance past cooldowns; guard tests exercise real budgets.
	now := time.Unix(100, 0)
	a.guard.clock = func() time.Time { now = now.Add(time.Minute); return now }
	return a, signer, checks
}
func invoke(t *testing.T, a *Authenticator, cmd byte, request any) (byte, []byte) {
	t.Helper()
	data, err := cbor.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	return a.HandleCommand(context.Background(), cmd, data)
}
func registration() map[int]any {
	return map[int]any{1: make([]byte, 32), 2: map[string]any{"id": "example.com"}, 3: map[string]any{"id": []byte{1}}, 4: []map[string]any{{"type": "public-key", "alg": -7}}, 7: map[string]bool{"rk": true}}
}

func TestSessionGate(t *testing.T) {
	for _, tt := range []struct {
		name    string
		denyAt  int
		changed bool
		probe   bool
	}{
		{"inactive before request", 1, false, false},
		{"inactive preflight", 1, false, true},
		{"locked during fingerprint", 3, false, false},
		{"switched during fingerprint", 3, true, false},
		{"locked after signing", 4, false, false},
		{"locked after preflight", 2, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, s, scans := testAuthenticator(t)
			if status, _ := invoke(t, a, 1, registration()); status != 0 {
				t.Fatal(status)
			}

			before := s.signs
			*scans = 0
			calls := 0
			a.session = func(context.Context) (string, error) {
				calls++
				if calls >= tt.denyAt {
					if tt.changed {
						return "different-session", nil
					}

					return "", errors.New("inactive")
				}

				return "owner-session", nil
			}
			r := map[int]any{1: "example.com", 2: make([]byte, 32)}
			if tt.probe {
				r[3] = []descriptor{{Type: "public-key", ID: a.store.credentials[0].ID}}
				r[5] = map[string]bool{"up": false, "uv": false}
			}

			status, out := invoke(t, a, 2, r)
			if status != 0x27 || len(out) != 0 {
				t.Fatalf("released assertion: status=%x bytes=%d", status, len(out))
			}

			if tt.denyAt == 1 && *scans != 0 {
				t.Fatal("scanned without an owner session")
			}

			if !tt.probe && tt.denyAt <= 3 && s.signs != before {
				t.Fatal("signed after session denial")
			}

			if status, _ := a.HandleCommand(context.Background(), 4, nil); status != 0 {
				t.Fatal("GetInfo must remain available")
			}
		})
	}
}

func TestMissingSessionGateDeniesCredentials(t *testing.T) {
	a, s, scans := testAuthenticator(t)
	a.session = nil
	status, out := invoke(t, a, 1, registration())
	if status != 0x27 || len(out) != 0 || *scans != 0 || len(s.keys) != 0 {
		t.Fatal("missing session gate allowed registration")
	}
}

func TestSessionDenialBeforeRegistrationCommit(t *testing.T) {
	a, _, _ := testAuthenticator(t)
	calls := 0
	a.session = func(context.Context) (string, error) {
		calls++
		if calls >= 4 {
			return "", errors.New("session locked after TPM work")
		}

		return "owner-session", nil
	}
	status, out := invoke(t, a, 1, registration())
	if status != 0x27 || len(out) != 0 || len(a.store.credentials) != 0 {
		t.Fatal("registration was committed after session denial")
	}

	a.session = func(context.Context) (string, error) { return "owner-session", nil }
	if status, _ := invoke(t, a, 1, registration()); status != 0 {
		t.Fatalf("retry could not register resident credential: %x", status)
	}
}
func TestRegisterAndAssert(t *testing.T) {
	a, s, checks := testAuthenticator(t)
	status, out := invoke(t, a, 1, registration())
	if status != 0 {
		t.Fatalf("register status %x", status)
	}

	var reg struct {
		Fmt       string         `cbor:"1,keyasint"`
		Data      []byte         `cbor:"2,keyasint"`
		Statement map[string]any `cbor:"3,keyasint"`
	}
	if err := cbor.Unmarshal(out, &reg); err != nil {
		t.Fatal(err)
	}

	if reg.Fmt != "packed" || reg.Data[32] != 0x45 || binary.BigEndian.Uint32(reg.Data[33:37]) != 0 {
		t.Fatal("bad attestation data")
	}

	idlen := int(binary.BigEndian.Uint16(reg.Data[53:55]))
	id := reg.Data[55 : 55+idlen]
	c := a.store.find("example.com", id)
	if c == nil {
		t.Fatal("credential not persisted")
	}

	k := s.keys[string(c.Key)]
	digest := sha256.Sum256(append(append([]byte(nil), reg.Data...), make([]byte, 32)...))
	if !ecdsa.VerifyASN1(&k.PublicKey, digest[:], reg.Statement["sig"].([]byte)) {
		t.Fatal("invalid self attestation")
	}

	// Simulate reload using the same TPM; no in-memory credential cache is required.
	dir := a.store.dir
	_ = a.store.Close()
	var err error
	a.store, err = openStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = a.store.Close() }() // Best-effort cleanup; preserve the operation result.

	hash := bytes.Repeat([]byte{3}, 32)
	status, out = invoke(t, a, 2, map[int]any{1: "example.com", 2: hash})
	if status != 0 {
		t.Fatalf("assert status %x", status)
	}

	var assertion struct {
		Data      []byte `cbor:"2,keyasint"`
		Signature []byte `cbor:"3,keyasint"`
	}
	if err := cbor.Unmarshal(out, &assertion); err != nil {
		t.Fatal(err)
	}

	digest = sha256.Sum256(append(assertion.Data, hash...))
	if !ecdsa.VerifyASN1(&k.PublicKey, digest[:], assertion.Signature) {
		t.Fatal("invalid assertion signature")
	}

	if *checks != 2 {
		t.Fatalf("expected fresh verification twice, got %d", *checks)
	}

	status, _ = invoke(t, a, 2, map[int]any{1: "evil.example", 2: hash, 3: []map[string]any{{"type": "public-key", "id": id}}})
	if status != 0x2e {
		t.Fatalf("cross-RP credential accepted: %x", status)
	}
}
func TestDeniedAndCancelledNeverSign(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "cancelled"}[cancelled], func(t *testing.T) {
			a, s, _ := testAuthenticator(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			a.verify = func(context.Context) error {
				if cancelled {
					cancel()
					return nil
				}

				return errors.New("no match")
			}
			req, _ := cbor.Marshal(registration())
			status, _ := a.HandleCommand(ctx, 1, req)
			if status == 0 || len(s.keys) != 0 || s.signs != 0 || len(a.store.credentials) != 0 {
				t.Fatal("unauthorized registration")
			}
		})
	}

	a, s, _ := testAuthenticator(t)
	invoke(t, a, 1, registration())
	before := s.signs
	a.verify = func(context.Context) error { return errors.New("no match") }
	status, _ := invoke(t, a, 2, map[int]any{1: "example.com", 2: make([]byte, 32)})
	if status == 0 || s.signs != before {
		t.Fatal("signed without verification")
	}
}
func TestRegistrationSaveFailure(t *testing.T) {
	a, _, _ := testAuthenticator(t)
	if err := os.Mkdir(filepath.Join(a.store.dir, "credentials.json"), 0700); err != nil {
		t.Fatal(err)
	}

	status, _ := invoke(t, a, 1, registration())
	if status == 0 {
		t.Fatal("reported successful registration after save failure")
	}
}
func TestExclusionAndResidentLimit(t *testing.T) {
	a, _, checks := testAuthenticator(t)
	invoke(t, a, 1, registration())
	req := registration()
	req[5] = []map[string]any{{"type": "public-key", "id": a.store.credentials[0].ID}}
	status, _ := invoke(t, a, 1, req)
	if status != 0x19 || *checks != 2 {
		t.Fatalf("exclusion must require touch: %x checks %d", status, *checks)
	}

	status, _ = invoke(t, a, 1, registration())
	if status != 0x28 {
		t.Fatalf("second resident must fail explicitly: %x", status)
	}
}
func TestCTAPMalformedAndCapabilities(t *testing.T) {
	a, _, _ := testAuthenticator(t)
	for _, data := range [][]byte{{}, {0xff}, {0xa2, 1, 0, 1, 0}} {
		if status, _ := a.HandleCommand(context.Background(), 1, data); status == 0 {
			t.Fatal("accepted malformed CBOR")
		}
	}

	req := registration()
	req[1] = []byte{1}
	if status, _ := invoke(t, a, 1, req); status != 2 {
		t.Fatalf("short challenge: %x", status)
	}

	status, out := a.HandleCommand(context.Background(), 4, nil)
	if status != 0 {
		t.Fatal(status)
	}

	var info map[int]cbor.RawMessage
	if err := cbor.Unmarshal(out, &info); err != nil {
		t.Fatal(err)
	}

	if _, ok := info[6]; ok {
		t.Fatal("advertises unsupported PIN protocol")
	}

	var versions []string
	if err := cbor.Unmarshal(info[1], &versions); err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || versions[0] != "FIDO_2_0" {
		t.Fatal(versions)
	}
}

func TestMissingCredentialRequiresConsent(t *testing.T) {
	a, _, checks := testAuthenticator(t)
	status, _ := invoke(t, a, 2, map[int]any{1: "example.com", 2: make([]byte, 32), 5: map[string]bool{"uv": true}})
	if status != 0x2e || *checks != 1 {
		t.Fatalf("absence disclosed without consent: status %x, checks %d", status, *checks)
	}

	a.verify = func(context.Context) error { return errors.New("denied") }
	status, _ = invoke(t, a, 2, map[int]any{1: "example.com", 2: make([]byte, 32)})
	if status != 0x27 {
		t.Fatalf("denied consent disclosed absence: %x", status)
	}
}

func TestAssertionDiagnosticsDoNotExposeCredentials(t *testing.T) {
	a, _, _ := testAuthenticator(t)
	req := registration()
	delete(req, 7)
	// A distinct handle avoids accidental matches against ordinary log metadata.
	req[3] = map[string]any{"id": []byte("private-user-handle-for-log-test")}
	if status, _ := invoke(t, a, 1, req); status != 0 {
		t.Fatal(status)
	}

	c := a.store.credentials[0]
	var output bytes.Buffer
	a.debug = log.New(&output, "", 0)
	status, _ := invoke(t, a, 2, map[int]any{1: c.RP, 2: bytes.Repeat([]byte{0xaa}, 32), 3: []descriptor{{Type: "public-key", ID: c.ID}}, 5: map[string]bool{"up": true, "uv": true}})
	if status != 0 || output.Len() == 0 {
		t.Fatalf("expected successful assertion with diagnostics, status=%x", status)
	}

	for _, secret := range [][]byte{c.ID, c.Key, c.User} {
		// Cover common logging formats, including base64 without JSON quotes.
		for _, encoded := range []string{
			string(secret), base64.StdEncoding.EncodeToString(secret),
			hex.EncodeToString(secret), fmt.Sprint(secret), //nolint:staticcheck // QF1010: check the decimal byte-slice log representation, not its string conversion.
		} {
			if strings.Contains(output.String(), encoded) {
				t.Error("credential bytes in diagnostic output")
			}
		}
	}
}

func TestAssertionPreflight(t *testing.T) {
	for _, tt := range []struct {
		name    string
		options map[string]bool
		allow   bool
		flags   byte
	}{
		{"probe", map[string]bool{"up": false, "uv": false}, true, 0},
		{"probe UV omitted", map[string]bool{"up": false}, true, 0},
		{"login", map[string]bool{"up": true, "uv": true}, true, 5},
		{"default UP", map[string]bool{"uv": false}, true, 5},
		{"UV required", map[string]bool{"up": false, "uv": true}, true, 5},
		{"discovery", map[string]bool{"up": false, "uv": false}, false, 5},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, s, checks := testAuthenticator(t)
			if status, _ := invoke(t, a, 1, registration()); status != 0 {
				t.Fatal(status)
			}

			c := a.store.credentials[0]
			hash := bytes.Repeat([]byte{42}, 32)
			req := map[int]any{1: c.RP, 2: hash, 5: tt.options}
			if tt.allow {
				req[3] = []descriptor{{Type: "public-key", ID: c.ID}}
			}

			before := *checks
			status, out := invoke(t, a, 2, req)
			if status != 0 {
				t.Fatal(status)
			}

			var result struct {
				Data      []byte      `cbor:"2,keyasint"`
				Signature []byte      `cbor:"3,keyasint"`
				User      *userEntity `cbor:"4,keyasint"`
			}
			if err := cbor.Unmarshal(out, &result); err != nil {
				t.Fatal(err)
			}

			wantChecks := before
			if tt.flags != 0 {
				wantChecks++
			}

			if *checks != wantChecks || len(result.Data) != 37 || result.Data[32] != tt.flags {
				t.Fatalf("checks=%d want=%d authData=%x", *checks, wantChecks, result.Data)
			}

			if tt.flags == 0 && result.User != nil {
				t.Fatal("probe disclosed user handle")
			}

			digest := sha256.Sum256(append(append([]byte(nil), result.Data...), hash...))
			pub := &s.keys[string(c.Key)].PublicKey
			if !ecdsa.VerifyASN1(pub, digest[:], result.Signature) {
				t.Fatal("invalid signature")
			}

			if tt.flags == 0 {
				result.Data[32] = 5
				digest = sha256.Sum256(append(result.Data, hash...))
				if ecdsa.VerifyASN1(pub, digest[:], result.Signature) {
					t.Fatal("probe can be upgraded to verified login")
				}

				// A successful probe must not authorize the subsequent login.
				a.verify = func(context.Context) error { return errors.New("denied") }
				req[5] = map[string]bool{"up": true, "uv": true}
				signs := s.signs
				if status, _ := invoke(t, a, 2, req); status != 0x27 || s.signs != signs {
					t.Fatal("probe bypassed fresh verification")
				}
			}
		})
	}
}

func TestPreflightRejectsUnknownAndCrossRPCredentials(t *testing.T) {
	a, s, checks := testAuthenticator(t)
	if status, _ := invoke(t, a, 1, registration()); status != 0 {
		t.Fatal(status)
	}

	c := a.store.credentials[0]
	before, signs := *checks, s.signs
	for _, d := range []struct {
		rp string
		id []byte
	}{
		{c.RP, []byte("unknown")}, {"other.example", c.ID},
	} {
		status, _ := invoke(t, a, 2, map[int]any{1: d.rp, 2: make([]byte, 32), 3: []descriptor{{Type: "public-key", ID: d.id}}, 5: map[string]bool{"up": false, "uv": false}})
		if status != 0x2e || *checks != before || s.signs != signs {
			t.Fatalf("status=%x checks=%d signs=%d", status, *checks, s.signs)
		}
	}
}

func testNotify(context.Context, string, string) (func(), error) { return func() {}, nil }

func TestRequiredParameters(t *testing.T) {
	for _, cmd := range []byte{cmdMakeCredential, cmdGetAssertion} {
		required := []int{1, 2}
		if cmd == cmdMakeCredential {
			required = []int{1, 2, 3, 4}
		}

		for _, key := range required {
			a, _, scans := testAuthenticator(t)
			req := registration()
			if cmd == cmdGetAssertion {
				req = map[int]any{1: "example.com", 2: make([]byte, 32)}
			}

			delete(req, key)
			status, _ := invoke(t, a, cmd, req)
			if status != 0x14 || *scans != 0 {
				t.Fatalf("cmd=%x missing=%d status=%x scans=%d", cmd, key, status, *scans)
			}
		}
	}

	for _, key := range []int{2, 3} {
		a, _, _ := testAuthenticator(t)
		req := registration()
		req[key] = map[string]any{}
		if status, _ := invoke(t, a, cmdMakeCredential, req); status != 0x14 {
			t.Fatalf("missing entity id: %x", status)
		}
	}

	a, _, _ := testAuthenticator(t)
	req := registration()
	req[1] = []byte{}
	if status, _ := invoke(t, a, cmdMakeCredential, req); status != statusInvalidParameter {
		t.Fatalf("empty hash confused with absent: %x", status)
	}
}

func TestEnterpriseAttestationRejected(t *testing.T) {
	for _, value := range []any{uint(0), uint(1), uint(2), nil} {
		a, _, scans := testAuthenticator(t)
		req := registration()
		req[10] = value
		if status, _ := invoke(t, a, cmdMakeCredential, req); status != statusInvalidParameter || *scans != 0 {
			t.Fatalf("enterprise=%v status=%x scans=%d", value, status, *scans)
		}
	}
}

func TestInvalidRPDoesNotSpendPromptBudget(t *testing.T) {
	for _, cmd := range []byte{cmdMakeCredential, cmdGetAssertion} {
		a, _, scans := testAuthenticator(t)
		a.guard.clock = func() time.Time { return time.Unix(100, 0) }
		req := registration()
		if cmd == cmdMakeCredential {
			req[2] = map[string]any{"id": "bad/name"}
		} else {
			req = map[int]any{1: "bad/name", 2: make([]byte, 32), 3: []map[string]any{{"type": "public-key", "id": []byte{1}}}, 5: map[string]bool{"up": false}}
		}

		if status, _ := invoke(t, a, cmd, req); status != statusInvalidParameter {
			t.Fatalf("invalid RP status=%x", status)
		}

		if a.guard.prompts.initialized || !a.guard.blockedUntil.IsZero() || *scans != 0 {
			t.Fatal("invalid RP spent prompt budget")
		}

		if a.guard.requests.tokens != requestBurst-1 {
			t.Fatal("invalid request escaped request budget")
		}

		if status, _ := invoke(t, a, cmdMakeCredential, registration()); status != statusOK {
			t.Fatalf("valid request blocked: %x", status)
		}
	}
}

func TestResponseErrorUsesConfiguredLogger(t *testing.T) {
	var output bytes.Buffer
	a := &Authenticator{logger: log.New(&output, "", 0)}
	status, data := a.response(func() {})
	if status != statusOther || len(data) != 0 {
		t.Fatal("invalid marshal response")
	}

	if !strings.Contains(output.String(), "encode CTAP response:") {
		t.Fatal("missing error diagnostic")
	}
}

func TestRequestFieldTypes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   int
		value any
		want  byte
	}{
		{"hash type", 1, "hash", statusInvalidCBOR},
		{"rp type", 2, "example.com", statusInvalidCBOR},
		{"rp null", 2, nil, statusInvalidCBOR},
		{"rp id type", 2, map[string]any{"id": 7}, statusInvalidCBOR},
		{"user id type", 3, map[string]any{"id": "user"}, statusInvalidCBOR},
		{"options type", 7, true, statusInvalidCBOR},
		{"pin protocol type", 9, "one", statusInvalidCBOR},
		{"unknown field", 42, map[string]any{"future": true}, statusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, scans := testAuthenticator(t)
			req := registration()
			req[tc.key] = tc.value
			status, _ := invoke(t, a, cmdMakeCredential, req)
			if status != tc.want {
				t.Fatalf("status=%x want=%x", status, tc.want)
			}

			if status != statusOK && *scans != 0 {
				t.Fatal("invalid request prompted for a fingerprint")
			}
		})
	}
}

func TestFullStoreDoesNotPrompt(t *testing.T) {
	a, signer, scans := testAuthenticator(t)
	a.store.credentials = make([]credential, maxCredentials)
	status, _ := invoke(t, a, cmdMakeCredential, registration())
	if status != statusKeyStoreFull || *scans != 0 || signer.signs != 0 || a.guard.prompts.initialized {
		t.Fatalf("full store: status=%x scans=%d signs=%d", status, *scans, signer.signs)
	}
}

func TestResidentLimitRequiresAuthorization(t *testing.T) {
	a, _, scans := testAuthenticator(t)
	a.store.credentials = []credential{{RP: "example.com", Resident: true}}
	a.verify = func(context.Context) error { *scans++; return errors.New("denied") }
	status, _ := invoke(t, a, cmdMakeCredential, registration())
	if status != statusOperationDenied || *scans != 1 {
		t.Fatalf("resident existence exposed: status=%x scans=%d", status, *scans)
	}
}
