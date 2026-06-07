package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) *server {
	t.Helper()
	_, signer, err := newSigningKey()
	if err != nil {
		t.Fatalf("newSigningKey: %v", err)
	}
	return &server{
		signer:   signer,
		attester: newAttester(signer),
		keyLine:  authorizedKeyLine(signer, "test"),
	}
}

func TestHandlePubKey(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()
	s.handlePubKey(rr, httptest.NewRequest(http.MethodGet, "/pubkey", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.HasPrefix(rr.Body.String(), "ssh-ed25519 ") {
		t.Fatalf("unexpected pubkey body: %q", rr.Body.String())
	}
}

func TestHandleSignReturnsArmoredSSHSIG(t *testing.T) {
	s := newTestServer(t)
	body, _ := json.Marshal(signRequest{
		Namespace: "git",
		Data:      base64.StdEncoding.EncodeToString([]byte("commit bytes")),
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(string(body)))
	s.handleSign(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp signResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.HasPrefix(resp.Signature, "-----BEGIN SSH SIGNATURE-----") {
		t.Fatalf("not an armored SSHSIG: %q", resp.Signature)
	}
}

func TestHandleAttestationRequiresNonce(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()
	s.handleAttestation(rr, httptest.NewRequest(http.MethodGet, "/attestation", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without nonce, got %d", rr.Code)
	}
}
