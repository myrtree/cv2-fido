package tpm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestPublicPoint(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pub := signingKeyTemplate()
	pub.ECCParameters.Point = tpm2.ECPoint{XRaw: k.X.Bytes(), YRaw: k.Y.Bytes()}
	x, y, err := publicPoint(pub)
	if err != nil || x.Cmp(k.X) != 0 || y.Cmp(k.Y) != 0 {
		t.Fatal("valid point rejected", err)
	}

	for _, mutate := range []func(*tpm2.Public){
		func(p *tpm2.Public) { p.Type = tpm2.AlgRSA },
		func(p *tpm2.Public) { p.ECCParameters = nil },
		func(p *tpm2.Public) { p.ECCParameters.CurveID = tpm2.CurveNISTP384 },
		func(p *tpm2.Public) { p.ECCParameters.Point.XRaw = nil },
		func(p *tpm2.Public) { p.ECCParameters.Point.XRaw = make([]byte, 33) },
		func(p *tpm2.Public) { p.ECCParameters.Point = tpm2.ECPoint{XRaw: []byte{1}, YRaw: []byte{1}} },
	} {
		bad := pub
		params := *pub.ECCParameters
		bad.ECCParameters = &params
		mutate(&bad)
		if _, _, err := publicPoint(bad); err == nil {
			t.Fatal("invalid public key accepted")
		}
	}
}

func TestSignatureASN1(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("signature compatibility"))
	r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	sig := &tpm2.Signature{Alg: tpm2.AlgECDSA, ECC: &tpm2.SignatureECC{HashAlg: tpm2.AlgSHA256, R: r, S: s}}
	der, err := signatureASN1(sig)
	if err != nil || !ecdsa.VerifyASN1(&k.PublicKey, digest[:], der) {
		t.Fatal("invalid DER signature", err)
	}

	for _, bad := range []*tpm2.Signature{nil, {}, {Alg: tpm2.AlgECDSA}} {
		if _, err := signatureASN1(bad); err == nil {
			t.Fatal("accepted incomplete signature")
		}
	}

	for _, mutate := range []func(*tpm2.Signature){
		func(s *tpm2.Signature) { s.Alg = tpm2.AlgRSASSA },
		func(s *tpm2.Signature) { s.ECC.HashAlg = tpm2.AlgSHA1 },
		func(s *tpm2.Signature) { s.ECC.R = nil },
		func(s *tpm2.Signature) { s.ECC.S = nil },
		func(s *tpm2.Signature) { s.ECC.R = big.NewInt(0) },
		func(s *tpm2.Signature) { s.ECC.S = big.NewInt(-1) },
		func(s *tpm2.Signature) { s.ECC.R = elliptic.P256().Params().N },
	} {
		bad := *sig
		ecc := *sig.ECC
		bad.ECC = &ecc
		mutate(&bad)
		if _, err := signatureASN1(&bad); err == nil {
			t.Fatal("accepted invalid signature")
		}
	}
}
