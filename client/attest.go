package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/blocky/nitrite"
	"golang.org/x/crypto/ssh"
)

type attestResponse struct {
	Attestation string `json:"attestation"` // base64 NSM COSE_Sign1 document
	PubKey      string `json:"pubkey"`       // authorized_keys line bound by user_data
}

// runAttest fetches a fresh attestation document from the enclave, verifies it
// against the AWS Nitro root certificate, and — only if it is valid, fresh, and
// bound to the key it handed us — prints the PCR0 measurement and the public key
// you can safely trust for git signature verification.
func runAttest(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: git-enclave-signer attest <https://enclave-host>")
	}
	base := args[0]

	// A random nonce makes the document we get back unforgeable as a replay.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	resp, err := fetchAttestation(base, nonce)
	if err != nil {
		return err
	}

	doc, err := base64.StdEncoding.DecodeString(resp.Attestation)
	if err != nil {
		return fmt.Errorf("decode attestation: %w", err)
	}
	if isDevStub(doc) {
		return fmt.Errorf("enclave returned an INSECURE dev-mode attestation (no NSM); refusing to trust %s", base)
	}

	// 1. Cryptographic chain: the document is signed by the NSM, whose cert
	//    chains to the AWS Nitro root. nitrite uses that root when Roots is nil.
	res, err := nitrite.Verify(doc, nitrite.VerifyOptions{CurrentTime: time.Now()})
	if err != nil {
		return fmt.Errorf("attestation verification failed: %w", err)
	}

	// 2. Freshness: the document must echo the nonce we just generated.
	if !bytes.Equal(res.Document.Nonce, nonce) {
		return fmt.Errorf("attestation nonce mismatch — possible replay")
	}

	// 3. Key binding: user_data must be sha256 of the public key we were handed,
	//    so we know this attested enclave is the one holding that key.
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.PubKey))
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	wantUserData := sha256.Sum256(pub.Marshal())
	if !bytes.Equal(res.Document.UserData, wantUserData[:]) {
		return fmt.Errorf("attestation does not bind this public key (user_data mismatch)")
	}

	fmt.Printf("✓ enclave attestation verified against the AWS Nitro root\n")
	fmt.Printf("  module: %s\n", res.Document.ModuleID)
	fmt.Printf("  PCR0:   %s\n", hex.EncodeToString(res.Document.PCRs[0]))
	fmt.Printf("\nTrusted signing key (use for allowed_signers / user.signingkey):\n\n%s\n", resp.PubKey)
	return nil
}

func fetchAttestation(base string, nonce []byte) (*attestResponse, error) {
	u := base + "/attestation?nonce=" + url.QueryEscape(hex.EncodeToString(nonce))
	httpResp, err := enclaveClient().Get(u)
	if err != nil {
		return nil, fmt.Errorf("call enclave: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enclave returned %s", httpResp.Status)
	}
	var out attestResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

// isDevStub detects the unsigned placeholder the enclave emits when it has no
// NSM device. A real client must never trust one.
func isDevStub(doc []byte) bool {
	var m map[string]string
	if err := json.Unmarshal(doc, &m); err != nil {
		return false
	}
	return m["dev_mode_insecure"] == "true"
}
