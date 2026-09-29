package authenticator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
	"math/big"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// Signer creates RP-bound keys and signs digests without exposing private keys.
type Signer interface {
	RegisterKey(rpHash []byte) ([]byte, *big.Int, *big.Int, error)
	SignASN1(key, rpHash, digest []byte) ([]byte, error)
}

// Authenticator serializes credential operations and owns their persistent store.
// Construct it with Open so authorization dependencies and the store are ready.
type Authenticator struct {
	mu      sync.Mutex
	guard   requestGuard
	signer  Signer
	store   *store
	verify  func(context.Context) error
	notify  func(context.Context, string, string) (func(), error)
	session func(context.Context) (string, error)
	debug   *log.Logger
}

type sessionContextKey struct{}

type descriptor struct {
	Type string `cbor:"type"`
	ID   []byte `cbor:"id"`
}
type rpEntity struct {
	ID string `cbor:"id"`
}
type userEntity struct {
	ID []byte `cbor:"id"`
}
type algorithm struct {
	Type string `cbor:"type"`
	Alg  int    `cbor:"alg"`
}
type makeRequest struct {
	Hash        []byte          `cbor:"1,keyasint"`
	RP          rpEntity        `cbor:"2,keyasint"`
	User        userEntity      `cbor:"3,keyasint"`
	Algorithms  []algorithm     `cbor:"4,keyasint"`
	Exclude     []descriptor    `cbor:"5,keyasint"`
	Options     map[string]bool `cbor:"7,keyasint"`
	PIN         []byte          `cbor:"8,keyasint"`
	PINProtocol uint            `cbor:"9,keyasint"`
	Enterprise  uint            `cbor:"10,keyasint"`
}
type assertionRequest struct {
	RP          string          `cbor:"1,keyasint"`
	Hash        []byte          `cbor:"2,keyasint"`
	Allow       []descriptor    `cbor:"3,keyasint"`
	Options     map[string]bool `cbor:"5,keyasint"`
	PIN         []byte          `cbor:"6,keyasint"`
	PINProtocol uint            `cbor:"7,keyasint"`
}

var encode = func() cbor.EncMode {
	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}

	return mode
}()
var decode = func() cbor.DecMode {
	mode, err := (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden, MaxNestedLevels: 8, MaxArrayElements: 128, MaxMapPairs: 64}).DecMode()
	if err != nil {
		panic(err)
	}

	return mode
}()
var aaguid = func() []byte { s := sha256.Sum256([]byte("cv2-fido experimental v1")); return s[:aaguidSize] }()

// HandleCommand is also serialized by the HID transport. The lock keeps direct
// callers from sharing verification or mutating the store concurrently.
func (a *Authenticator) HandleCommand(ctx context.Context, cmd byte, data []byte) (status byte, out []byte) {
	defer func() { a.trace("CTAP cmd=0x%02x status=0x%02x response_bytes=%d", cmd, status, len(out)) }()

	if !a.mu.TryLock() {
		return statusChannelBusy, nil
	}

	defer a.mu.Unlock()

	if ctx.Err() != nil {
		return contextStatus(ctx), nil
	}

	if len(data) > maxMessage {
		return statusRequestTooLarge, nil
	}

	if cmd != cmdGetInfo && !a.guard.request() {
		return statusChannelBusy, nil
	}

	if cmd != cmdGetInfo && a.store.failed != nil {
		return statusOther, nil
	}

	if cmd == cmdMakeCredential || cmd == cmdGetAssertion {
		if a.session == nil {
			return statusOperationDenied, nil
		}

		id, err := a.session(ctx)
		if err != nil || id == "" {
			a.trace("session denied: %v", err)
			return statusOperationDenied, nil
		}

		ctx = context.WithValue(ctx, sessionContextKey{}, id)
		defer func() {
			if status == statusOK && a.checkSession(ctx) != nil {
				status, out = statusOperationDenied, nil
			}
		}()
	}

	switch cmd {
	case cmdGetInfo:
		if len(data) != 0 {
			return statusInvalidLength, nil
		}

		return response(map[int]any{
			infoVersions: []string{"FIDO_2_0"}, infoAAGUID: aaguid,
			infoOptions:    map[string]bool{"rk": true, "up": true, "uv": true, "plat": false},
			infoMaxMsgSize: maxMessage,
		})
	case cmdMakeCredential:
		var req makeRequest
		if len(data) == 0 || data[0]>>cborMajorTypeShift != cborMajorTypeMap || decode.Unmarshal(data, &req) != nil {
			return statusInvalidCBOR, nil
		}

		return a.makeCredential(ctx, req)
	case cmdGetAssertion:
		var req assertionRequest
		if len(data) == 0 || data[0]>>cborMajorTypeShift != cborMajorTypeMap || decode.Unmarshal(data, &req) != nil {
			return statusInvalidCBOR, nil
		}

		return a.getAssertion(ctx, req)
	default:
		return statusInvalidCommand, nil
	}
}

func (a *Authenticator) trace(format string, args ...any) {
	if a.debug != nil {
		a.debug.Printf(format, args...)
	}
}

func response(value any) (byte, []byte) {
	out, err := encode.Marshal(value)
	if err != nil {
		return statusOther, nil
	}

	return statusOK, out
}

func contextStatus(ctx context.Context) byte {
	if errors.Is(ctx.Err(), context.Canceled) {
		return statusKeepaliveCancel
	}

	return statusUserActionTimeout
}

func (a *Authenticator) authorize(ctx context.Context, rp, action string) byte {
	if ctx.Err() != nil {
		return contextStatus(ctx)
	}

	if !a.guard.prompt() {
		return statusOperationDenied
	}

	success := false
	defer func() { a.guard.finish(success) }()

	if a.notify == nil {
		return statusOperationDenied
	}

	closeNotification, err := a.notify(ctx, rp, action)
	if err != nil {
		log.Printf("notification: %v", err)
		return statusOperationDenied
	}

	defer closeNotification()

	if ctx.Err() != nil {
		return contextStatus(ctx)
	}

	if err := a.checkSession(ctx); err != nil {
		return statusOperationDenied
	}

	log.Printf("%s for %q: touch the fingerprint reader", action, rp)
	err = a.verify(ctx)
	if ctx.Err() != nil {
		return contextStatus(ctx)
	}

	if err != nil {
		log.Printf("fingerprint: %v", err)
		return statusOperationDenied
	}

	if err := a.checkSession(ctx); err != nil {
		return statusOperationDenied
	}

	a.trace("fingerprint verified")
	success = true
	return statusOK
}

func (a *Authenticator) checkSession(ctx context.Context) error {
	if a.session == nil {
		return errors.New("missing session gate")
	}

	expected, _ := ctx.Value(sessionContextKey{}).(string)
	current, err := a.session(ctx)
	if err != nil {
		a.trace("session denied: %v", err)
		return err
	}

	if expected == "" || current != expected {
		return errors.New("owner session changed")
	}

	return nil
}

func (a *Authenticator) makeCredential(ctx context.Context, r makeRequest) (byte, []byte) {
	a.trace("makeCredential rp=%q exclude=%d rk=%t uv=%t", r.RP.ID, len(r.Exclude), r.Options["rk"], r.Options["uv"])
	if len(r.Hash) != sha256.Size || r.RP.ID == "" || len(r.RP.ID) > maxRPIDSize || len(r.User.ID) == 0 || len(r.User.ID) > maxUserIDSize || len(r.Exclude) > maxCredentialList {
		return statusInvalidParameter, nil
	}

	if r.PIN != nil || r.PINProtocol != 0 {
		return statusPINAuthInvalid, nil
	}

	if r.Enterprise != 0 {
		return statusUnsupportedOption, nil
	}

	if _, ok := r.Options["up"]; ok {
		return statusInvalidOption, nil
	}

	supported := false
	for _, alg := range r.Algorithms {
		if alg.Type == "public-key" && alg.Alg == coseES256 {
			supported = true
		}
	}

	if !supported {
		return statusUnsupportedAlgorithm, nil
	}

	if status := a.authorize(ctx, r.RP.ID, "register"); status != statusOK {
		return status, nil
	}

	for _, d := range r.Exclude {
		if d.Type == "public-key" && a.store.find(r.RP.ID, d.ID) != nil {
			return statusCredentialExcluded, nil
		}
	}

	if len(a.store.credentials) >= maxCredentials {
		return statusKeyStoreFull, nil
	}

	if r.Options["rk"] {
		for _, c := range a.store.credentials {
			if c.Resident && c.RP == r.RP.ID {
				return statusKeyStoreFull, nil
			}
		}
	}

	rpHash := sha256.Sum256([]byte(r.RP.ID))
	key, x, y, err := a.signer.RegisterKey(rpHash[:])
	if err != nil {
		log.Printf("create TPM key: %v", err)
		return statusOther, nil
	}

	if ctx.Err() != nil {
		return contextStatus(ctx), nil
	}

	id := make([]byte, credentialIDSize)
	if _, err := rand.Read(id); err != nil {
		return statusOther, nil
	}

	if x == nil || y == nil || x.Sign() < 0 || y.Sign() < 0 || x.BitLen() > p256Bits || y.BitLen() > p256Bits {
		return statusOther, nil
	}

	pub, err := encode.Marshal(map[int]any{
		coseKeyType: coseEC2, coseAlgorithm: coseES256, coseCurve: coseP256,
		coseX: x.FillBytes(make([]byte, p256CoordinateSize)),
		coseY: y.FillBytes(make([]byte, p256CoordinateSize)),
	})
	if err != nil {
		return statusOther, nil
	}

	authData := authenticatorData(rpHash, flagUserPresent|flagUserVerified|flagAttestedCredentialData)
	authData = append(authData, aaguid...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(id)))
	authData = append(authData, id...)
	authData = append(authData, pub...)
	digest := sha256.Sum256(append(append([]byte(nil), authData...), r.Hash...))
	sig, err := a.signer.SignASN1(key, rpHash[:], digest[:])
	if err != nil {
		log.Printf("self attestation: %v", err)
		return statusOther, nil
	}

	if ctx.Err() != nil {
		return contextStatus(ctx), nil
	}

	status, out := response(map[int]any{makeFormat: "packed", makeAuthData: authData, makeAttStatement: map[string]any{"alg": coseES256, "sig": sig}})
	if status != statusOK {
		return status, nil
	}

	if err := a.checkSession(ctx); err != nil {
		return statusOperationDenied, nil
	}

	if err := a.store.save(credential{ID: id, RP: r.RP.ID, User: r.User.ID, Key: key, Resident: r.Options["rk"]}); err != nil {
		log.Printf("save credential: %v", err)
		return statusOther, nil
	}

	if ctx.Err() != nil {
		return contextStatus(ctx), nil
	}

	return status, out
}

func (a *Authenticator) getAssertion(ctx context.Context, r assertionRequest) (byte, []byte) {
	if len(r.Hash) != sha256.Size || r.RP == "" || len(r.RP) > maxRPIDSize || len(r.Allow) > maxCredentialList {
		return statusInvalidParameter, nil
	}

	if r.PIN != nil || r.PINProtocol != 0 {
		return statusPINAuthInvalid, nil
	}

	if _, ok := r.Options["rk"]; ok {
		return statusInvalidOption, nil
	}

	var c *credential
	if len(r.Allow) > 0 {
		for _, d := range r.Allow {
			if d.Type == "public-key" {
				c = a.store.find(r.RP, d.ID)
				if c != nil {
					break
				}
			}
		}
	} else {
		for i := range a.store.credentials {
			candidate := &a.store.credentials[i]
			if candidate.Resident && candidate.RP == r.RP {
				c = candidate
				break
			}
		}
	}

	up := true
	if value, ok := r.Options["up"]; ok {
		up = value
	}

	a.trace("getAssertion rp=%q allow=%d matched=%t up=%t uv=%t", r.RP, len(r.Allow), c != nil, up, r.Options["uv"])
	if c != nil {
		a.trace("selected credential resident=%t", c.Resident)
	}

	// Browsers probe an explicit allowList before requesting an actual login.
	// Never mark that silent signature as user-present or user-verified, and
	// never use a probe to authorize a later request or discover accounts.
	probe := !up && !r.Options["uv"] && len(r.Allow) > 0
	flags := byte(flagUserPresent | flagUserVerified)
	if probe {
		flags = 0
		a.trace("credential preflight: no fingerprint required")
	} else {
		if status := a.authorize(ctx, r.RP, "authenticate"); status != statusOK {
			return status, nil
		}
	}

	if ctx.Err() != nil {
		return contextStatus(ctx), nil
	}

	if c == nil {
		return statusNoCredentials, nil
	}

	rpHash := sha256.Sum256([]byte(r.RP))
	authData := authenticatorData(rpHash, flags)
	digest := sha256.Sum256(append(append([]byte(nil), authData...), r.Hash...))
	sig, err := a.signer.SignASN1(c.Key, rpHash[:], digest[:])
	if err != nil {
		log.Printf("TPM assertion: %v", err)
		return statusOther, nil
	}

	if ctx.Err() != nil {
		return contextStatus(ctx), nil
	}

	result := map[int]any{assertionCredential: descriptor{Type: "public-key", ID: c.ID}, assertionAuthData: authData, assertionSignature: sig}
	a.trace("assertion signed flags=0x%02x", authData[sha256.Size])
	if c.Resident && !probe {
		result[assertionUser] = userEntity{ID: c.User}
	}

	return response(result)
}

func authenticatorData(rp [sha256.Size]byte, flags byte) []byte {
	out := make([]byte, sha256.Size+1+authDataCounterSize)
	copy(out, rp[:])
	out[sha256.Size] = flags
	// A constant zero explicitly means the Authenticator has no signature counter.
	return out
}
