package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// listenAddr is where the app serves plain HTTP. nitriding terminates external
// TLS inside the enclave and reverse-proxies decrypted requests here (its
// -appwebsrv flag points at this address). Nothing outside the enclave ever
// speaks to this port directly.
const listenAddr = "127.0.0.1:8081"

type server struct {
	signer   ssh.Signer
	attester *attester
	keyLine  string // authorized_keys form of the public key
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	_, signer, err := newSigningKey()
	if err != nil {
		slog.Error("generate signing key", "err", err)
		os.Exit(1)
	}
	s := &server{
		signer:   signer,
		attester: newAttester(signer),
		keyLine:  authorizedKeyLine(signer, "secure-git-signer-enclave"),
	}
	if s.attester.dev {
		slog.Warn("no /dev/nsm present — INSECURE dev mode; attestation documents are unsigned stubs")
	}
	slog.Info("enclave signing key ready", "pubkey", s.keyLine)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /pubkey", s.handlePubKey)
	mux.HandleFunc("GET /attestation", s.handleAttestation)
	mux.HandleFunc("POST /sign", s.handleSign)

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	slog.Info("enclave app listening", "addr", listenAddr)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// handlePubKey returns the enclave's signing public key in authorized_keys form,
// for use in an allowed_signers file or git's user.signingkey.
func (s *server) handlePubKey(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, s.keyLine+"\n")
}

type attestResponse struct {
	Attestation string `json:"attestation"` // base64 NSM document (COSE_Sign1)
	PubKey      string `json:"pubkey"`       // authorized_keys line bound by user_data
}

// handleAttestation returns a fresh NSM attestation document for the supplied
// nonce. The nonce is mandatory: it ties the document to this request so a
// client cannot be fooled by a replayed one.
func (s *server) handleAttestation(w http.ResponseWriter, r *http.Request) {
	nonceHex := r.URL.Query().Get("nonce")
	if nonceHex == "" {
		http.Error(w, "missing nonce query parameter", http.StatusBadRequest)
		return
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		http.Error(w, "nonce must be hex", http.StatusBadRequest)
		return
	}

	doc, err := s.attester.attest(nonce)
	if err != nil {
		slog.Error("attestation failed", "err", err)
		http.Error(w, "attestation failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, attestResponse{
		Attestation: base64.StdEncoding.EncodeToString(doc),
		PubKey:      s.keyLine,
	})
}

type signRequest struct {
	Namespace string `json:"namespace"` // SSHSIG namespace; git uses "git"
	Data      string `json:"data"`      // base64-encoded bytes to sign
}

type signResponse struct {
	Signature string `json:"signature"` // armored SSHSIG
}

// handleSign signs the supplied bytes and returns an armored SSHSIG. The private
// key never leaves this process; only the signature crosses the boundary.
func (s *server) handleSign(w http.ResponseWriter, r *http.Request) {
	var req signRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Namespace == "" {
		req.Namespace = "git"
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		http.Error(w, "data must be base64", http.StatusBadRequest)
		return
	}

	armored, err := sshSignature(s.signer, req.Namespace, data)
	if err != nil {
		slog.Error("signing failed", "err", err)
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, signResponse{Signature: armored})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
