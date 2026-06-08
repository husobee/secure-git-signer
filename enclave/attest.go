package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"golang.org/x/crypto/ssh"
)

// attester produces NSM attestation documents that bind the enclave's signing
// public key (and a caller-supplied nonce) to the enclave's measurements — most
// importantly PCR0, the hash of the enclave image. A remote client verifies the
// document against the AWS Nitro root certificate to prove the key it is about
// to trust really belongs to known code running in a genuine enclave.
type attester struct {
	pubKey []byte // SSH wire-format public key, bound into user_data
	dev    bool   // true when /dev/nsm is absent (local development)
}

// newAttester inspects the host for an NSM device. With no device present it
// drops into dev mode so the app still runs on a laptop — but dev attestations
// are clearly marked insecure and a real client must refuse them.
func newAttester(signer ssh.Signer) *attester {
	a := &attester{pubKey: signer.PublicKey().Marshal()}
	if _, err := os.Stat("/dev/nsm"); err != nil {
		a.dev = true
	}
	return a
}

// userData is the value bound into every attestation: SHA-256 over the SSH
// public key. A verifier recomputes this from the key it received and checks it
// matches, closing the gap between "an enclave attested" and "*this* key is the
// one that enclave holds".
func (a *attester) userData() []byte {
	sum := sha256.Sum256(a.pubKey)
	return sum[:]
}

// attest requests a fresh attestation document for the given nonce. On a real
// Nitro host this is a COSE_Sign1 document signed by the NSM, embedding PCR0 and
// our user_data. In dev mode it returns a clearly-marked stub instead.
func (a *attester) attest(nonce []byte) ([]byte, error) {
	if a.dev {
		return devAttestation(a.userData(), nonce), nil
	}

	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("open NSM session: %w", err)
	}
	defer sess.Close() //nolint:errcheck

	res, err := sess.Send(&request.Attestation{
		Nonce:     nonce,
		UserData:  a.userData(),
		PublicKey: a.pubKey,
	})
	if err != nil {
		return nil, fmt.Errorf("NSM attestation request: %w", err)
	}
	if res.Error != "" {
		return nil, fmt.Errorf("NSM error: %s", res.Error)
	}
	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("NSM returned an empty attestation")
	}
	return res.Attestation.Document, nil
}

// devAttestation is a non-COSE placeholder used only when no NSM device exists.
// It carries the same user_data/nonce binding so the API shape is identical, but
// it is unsigned and explicitly flagged. Clients must treat it as untrusted.
func devAttestation(userData, nonce []byte) []byte {
	b, _ := json.Marshal(map[string]string{
		"dev_mode_insecure": "true",
		"user_data":         hex.EncodeToString(userData),
		"nonce":             hex.EncodeToString(nonce),
	})
	return b
}
