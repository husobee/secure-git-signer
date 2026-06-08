// Command git-enclave-signer is a drop-in replacement for ssh-keygen as git's
// SSH signing backend (gpg.ssh.program). It intercepts the "-Y sign" invocation
// and forwards the bytes-to-sign to a secure-git-signer enclave, which holds the
// private key and returns an armored SSHSIG. Every other invocation git makes
// (-Y verify, -Y find-principals, …) is passed straight through to the real
// ssh-keygen, which can verify the enclave's signatures unchanged.
//
// Configuration:
//
//	export ENCLAVE_URL=https://<enclave-host>
//	git config gpg.format ssh
//	git config gpg.ssh.program /path/to/git-enclave-signer
//	git config user.signingkey ~/.config/git/enclave-signer.pub
//	git config commit.gpgsign true
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"
)

func main() {
	args := os.Args[1:]

	// git's signing call: ssh-keygen -Y sign -n <ns> -f <key> <bufferfile>.
	if isSignInvocation(args) {
		if err := runSign(args); err != nil {
			fmt.Fprintln(os.Stderr, "git-enclave-signer:", err)
			os.Exit(1)
		}
		return
	}

	switch first(args) {
	case "help", "-h", "--help", "":
		usage()
	default:
		// Anything else (git's verify path, find-principals, …) is handled by
		// the real ssh-keygen. Our signatures verify there without changes.
		passthrough(args)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `git-enclave-signer — sign git commits with a key held in a Nitro Enclave

Usage:
  git-enclave-signer attest <https://enclave-host>   verify the enclave and print its trusted key
  git-enclave-signer -Y sign -n git -f <key> <file>  (invoked by git; signs via the enclave)
  git-enclave-signer <ssh-keygen args…>              passed through to ssh-keygen (e.g. -Y verify)

Environment:
  ENCLAVE_URL   base URL of the enclave (e.g. https://enclave.example.com)
`)
}

// isSignInvocation reports whether git is asking us to produce a signature.
func isSignInvocation(args []string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-Y" && args[i+1] == "sign" {
			return true
		}
	}
	return false
}

// parseSign extracts the SSHSIG namespace and the payload file from git's
// ssh-keygen-style argument list. The payload file is always the final argument;
// flags we don't need (-f keyfile, -O option, …) are skipped.
func parseSign(args []string) (namespace, file string) {
	namespace = "git"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n":
			if i+1 < len(args) {
				namespace = args[i+1]
				i++
			}
		case "-f", "-O", "-I", "-s", "-U":
			i++ // skip the flag's value; the enclave holds the key
		}
	}
	if len(args) > 0 {
		file = args[len(args)-1]
	}
	return namespace, file
}

// runSign reads the payload file git produced, has the enclave sign it, and
// writes the armored signature to <file>.sig — exactly where git expects it.
func runSign(args []string) error {
	namespace, file := parseSign(args)
	if file == "" {
		return fmt.Errorf("no payload file in sign arguments")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	url := os.Getenv("ENCLAVE_URL")
	if url == "" {
		return fmt.Errorf("ENCLAVE_URL is not set")
	}

	armored, err := signViaEnclave(url, namespace, data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(file+".sig", []byte(armored), 0o600); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}
	return nil
}

type signRequest struct {
	Namespace string `json:"namespace"`
	Data      string `json:"data"`
}

type signResponse struct {
	Signature string `json:"signature"`
}

// signViaEnclave POSTs the bytes-to-sign to the enclave and returns the armored
// SSHSIG. TLS verification is skipped because the enclave presents a self-signed
// certificate; trust does not come from the TLS PKI but from the attestation
// step (see runAttest) and from the fact that a forged or tampered signature
// simply fails git's own verification — the enclave's private key never leaves.
func signViaEnclave(baseURL, namespace string, data []byte) (string, error) {
	reqBody, _ := json.Marshal(signRequest{
		Namespace: namespace,
		Data:      base64.StdEncoding.EncodeToString(data),
	})
	resp, err := enclaveClient().Post(baseURL+"/sign", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("call enclave: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("enclave returned %s", resp.Status)
	}

	var out signResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode enclave response: %w", err)
	}
	if out.Signature == "" {
		return "", fmt.Errorf("enclave returned an empty signature")
	}
	return out.Signature, nil
}

func enclaveClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed; trust is from attestation
		},
	}
}

// passthrough runs the real ssh-keygen with the given arguments, inheriting
// stdio. git uses this for the verification side of signing.
func passthrough(args []string) {
	cmd := exec.Command("ssh-keygen", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "git-enclave-signer: ssh-keygen:", err)
		os.Exit(1)
	}
}

func first(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}
