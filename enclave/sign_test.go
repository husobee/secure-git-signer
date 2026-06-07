package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSSHSignatureVerifiesWithSSHKeygen is a golden test: the armored signature
// the enclave produces must verify under the real `ssh-keygen -Y verify` — the
// exact path `git log --show-signature` uses. If this passes, git will accept
// the enclave's signatures without any custom verification code.
func TestSSHSignatureVerifiesWithSSHKeygen(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}

	_, signer, err := newSigningKey()
	if err != nil {
		t.Fatalf("newSigningKey: %v", err)
	}

	const namespace = "git"
	message := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nsigned in an enclave\n")

	armored, err := sshSignature(signer, namespace, message)
	if err != nil {
		t.Fatalf("sshSignature: %v", err)
	}
	if !strings.HasPrefix(armored, "-----BEGIN SSH SIGNATURE-----") {
		t.Fatalf("not an armored SSHSIG:\n%s", armored)
	}

	dir := t.TempDir()
	msgFile := filepath.Join(dir, "msg")
	sigFile := filepath.Join(dir, "msg.sig")
	allowed := filepath.Join(dir, "allowed_signers")
	const principal = "tester@example.com"

	if err := os.WriteFile(msgFile, message, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigFile, []byte(armored), 0o600); err != nil {
		t.Fatal(err)
	}
	// allowed_signers line: "<principal> <keytype> <base64-key>"
	line := principal + " " + authorizedKeyLine(signer, "")
	if err := os.WriteFile(allowed, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	msg, err := os.Open(msgFile)
	if err != nil {
		t.Fatal(err)
	}
	defer msg.Close()

	cmd := exec.Command("ssh-keygen", "-Y", "verify",
		"-f", allowed,
		"-I", principal,
		"-n", namespace,
		"-s", sigFile)
	cmd.Stdin = msg
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y verify rejected the enclave signature: %v\n%s", err, out)
	}
}

// TestAuthorizedKeyLine sanity-checks the public-key line format the enclave
// hands out for allowed_signers / user.signingkey.
func TestAuthorizedKeyLine(t *testing.T) {
	_, signer, err := newSigningKey()
	if err != nil {
		t.Fatalf("newSigningKey: %v", err)
	}
	line := authorizedKeyLine(signer, "enclave")
	if !strings.HasPrefix(line, "ssh-ed25519 ") {
		t.Fatalf("expected ssh-ed25519 key line, got %q", line)
	}
	if !strings.HasSuffix(line, " enclave") {
		t.Fatalf("expected trailing comment, got %q", line)
	}
}
