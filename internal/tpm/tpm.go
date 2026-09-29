package tpm

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/hkdf"
)

const (
	seedSizeBytes      = 20
	p256CoordinateSize = 32
)

type TPM struct {
	devicePath string
	mu         sync.Mutex
}

func (t *TPM) open() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM(t.devicePath)
}

func New(devicePath string) (*TPM, error) {
	t := &TPM{
		devicePath: devicePath,
	}

	tpm, err := t.open()
	if err != nil {
		return nil, err
	}

	_ = tpm.Close()

	return t, nil
}

func primaryKeyTmpl(seed, applicationParam []byte) tpm2.Public {
	info := append([]byte("tpm-fido-application-key"), applicationParam...)

	r := hkdf.New(sha256.New, seed, []byte{}, info)
	unique := tpm2.ECPoint{
		XRaw: make([]byte, p256CoordinateSize),
		YRaw: make([]byte, p256CoordinateSize),
	}
	if _, err := io.ReadFull(r, unique.XRaw); err != nil {
		panic(err)
	}

	if _, err := io.ReadFull(r, unique.YRaw); err != nil {
		panic(err)
	}

	return tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagRestricted | tpm2.FlagDecrypt |
			tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			CurveID: tpm2.CurveNISTP256,
			Point:   unique,
		},
	}
}

// RegisterKey creates a non-migratable P-256 key bound to the RP hash.
// It returns the wrapped credential and public coordinates.
func (t *TPM) RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error) {
	if len(applicationParam) != sha256.Size {
		return nil, nil, nil, errors.New("RP hash must be 32 bytes")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	tpm, err := t.open()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open TPM: %w", err)
	}

	defer func() { _ = tpm.Close() }() // Best-effort cleanup; preserve the operation result.

	randSeed := make([]byte, seedSizeBytes)
	if _, err := rand.Read(randSeed); err != nil {
		return nil, nil, nil, fmt.Errorf("generate TPM credential seed: %w", err)
	}

	primaryTmpl := primaryKeyTmpl(randSeed, applicationParam)

	parentHandle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", primaryTmpl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create TPM parent: %w", err)
	}

	defer func() { _ = tpm2.FlushContext(tpm, parentHandle) }() // Best effort; closing the resource-manager connection also releases handles.

	private, public, _, _, _, err := tpm2.CreateKey(tpm, parentHandle, tpm2.PCRSelection{}, "", "", signingKeyTemplate())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create TPM signing key: %w", err)
	}

	encoded, err := encodeKey(wrappedKey{private, public, randSeed})
	if err != nil {
		return nil, nil, nil, err
	}

	// CreateKey already returns the public area; loading the key to read it
	// back adds TPM commands and a transient handle without new information.
	pub, err := tpm2.DecodePublic(public)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode TPM public key: %w", err)
	}

	x, y, err := publicPoint(pub)
	if err != nil {
		return nil, nil, nil, err
	}

	return encoded, x, y, nil
}

func (t *TPM) SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error) {
	if len(applicationParam) != sha256.Size || len(digest) != sha256.Size {
		return nil, errors.New("RP hash and signing digest must be 32 bytes")
	}

	k, err := decodeKey(keyHandle)
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	tpm, err := t.open()
	if err != nil {
		return nil, fmt.Errorf("open TPM: %w", err)
	}

	defer func() { _ = tpm.Close() }() // Best-effort cleanup; preserve the operation result.

	srkTemplate := primaryKeyTmpl(k.seed, applicationParam)

	parentHandle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("create TPM parent: %w", err)
	}

	defer func() { _ = tpm2.FlushContext(tpm, parentHandle) }() // Best effort; closing the resource-manager connection also releases handles.

	key, _, err := tpm2.Load(tpm, parentHandle, "", k.public, k.private)
	if err != nil {
		return nil, fmt.Errorf("load TPM signing key: %w", err)
	}

	defer func() { _ = tpm2.FlushContext(tpm, key) }() // Best effort; closing the resource-manager connection also releases handles.

	scheme := &tpm2.SigScheme{
		Alg:  tpm2.AlgECDSA,
		Hash: tpm2.AlgSHA256,
	}

	sig, err := tpm2.Sign(tpm, key, "", digest, nil, scheme)
	if err != nil {
		return nil, fmt.Errorf("TPM sign: %w", err)
	}

	return signatureASN1(sig)
}

func signingKeyTemplate() tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
			tpm2.FlagSign,
		ECCParameters: &tpm2.ECCParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpm2.AlgSHA256,
			},
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: make([]byte, p256CoordinateSize),
				YRaw: make([]byte, p256CoordinateSize),
			},
		},
	}
}

func publicPoint(pub tpm2.Public) (*big.Int, *big.Int, error) {
	p := pub.ECCParameters
	if pub.Type != tpm2.AlgECC || p == nil || p.CurveID != tpm2.CurveNISTP256 ||
		len(p.Point.XRaw) == 0 || len(p.Point.XRaw) > p256CoordinateSize || len(p.Point.YRaw) == 0 || len(p.Point.YRaw) > p256CoordinateSize {
		return nil, nil, errors.New("TPM returned an invalid P-256 public key")
	}

	x, y := new(big.Int).SetBytes(p.Point.XRaw), new(big.Int).SetBytes(p.Point.YRaw)
	if !elliptic.P256().IsOnCurve(x, y) { //nolint:staticcheck // SA1019: validate TPM ECDSA coordinates; this is not ECDH key agreement.
		return nil, nil, errors.New("TPM public point is not on P-256")
	}

	return x, y, nil
}

func signatureASN1(sig *tpm2.Signature) ([]byte, error) {
	if sig == nil || sig.Alg != tpm2.AlgECDSA || sig.ECC == nil || sig.ECC.HashAlg != tpm2.AlgSHA256 {
		return nil, errors.New("TPM returned an invalid ECDSA/SHA256 signature")
	}

	r, s := sig.ECC.R, sig.ECC.S
	n := elliptic.P256().Params().N
	if r == nil || s == nil || r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return nil, errors.New("TPM returned out-of-range ECDSA scalars")
	}

	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}
