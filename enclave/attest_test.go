package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestAttesterUserDataBindsPublicKey(t *testing.T) {
	_, signer, err := newSigningKey()
	if err != nil {
		t.Fatalf("newSigningKey: %v", err)
	}
	a := newAttester(signer)

	want := sha256.Sum256(signer.PublicKey().Marshal())
	if !bytes.Equal(a.userData(), want[:]) {
		t.Fatalf("user_data is not sha256 of the public key")
	}
}

func TestAttesterDevFallback(t *testing.T) {
	_, signer, err := newSigningKey()
	if err != nil {
		t.Fatalf("newSigningKey: %v", err)
	}
	a := newAttester(signer)
	if !a.dev {
		t.Skip("running on a real NSM host; dev fallback not exercised")
	}

	nonce := []byte("nonce-12345")
	doc, err := a.attest(nonce)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}

	var m map[string]string
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatalf("dev attestation is not JSON: %v", err)
	}
	if m["dev_mode_insecure"] != "true" {
		t.Fatalf("dev attestation must flag itself insecure, got %q", m["dev_mode_insecure"])
	}
	if m["nonce"] != hex.EncodeToString(nonce) {
		t.Fatalf("nonce not echoed: got %q", m["nonce"])
	}
	want := sha256.Sum256(signer.PublicKey().Marshal())
	if m["user_data"] != hex.EncodeToString(want[:]) {
		t.Fatalf("user_data not bound in dev attestation")
	}
}
