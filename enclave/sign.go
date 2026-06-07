package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// sshsigMagic is the 6-byte preamble OpenSSH prepends to both the signed blob
// and the outer armored container (see PROTOCOL.sshsig).
const sshsigMagic = "SSHSIG"

// newSigningKey generates a fresh ed25519 keypair and wraps the private half in
// an ssh.Signer. The private key exists only in memory inside the enclave and
// is never serialized, logged, or exported.
func newSigningKey() (ed25519.PrivateKey, ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap signer: %w", err)
	}
	return priv, signer, nil
}

// authorizedKeyLine returns the public key in authorized_keys form,
// "ssh-ed25519 <base64> [comment]", suitable for an allowed_signers entry or
// git's user.signingkey file.
func authorizedKeyLine(signer ssh.Signer, comment string) string {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if comment != "" {
		line += " " + comment
	}
	return line
}

// sshSignature produces an armored SSHSIG over message in the given namespace,
// per the OpenSSH PROTOCOL.sshsig specification. The output is byte-for-byte
// compatible with `ssh-keygen -Y sign` and so verifies with
// `ssh-keygen -Y verify` — the path git uses for `git log --show-signature`.
func sshSignature(signer ssh.Signer, namespace string, message []byte) (string, error) {
	// What actually gets signed is H(message) wrapped in a small framed blob,
	// not the message itself.
	h := sha512.Sum512(message)

	var signed bytes.Buffer
	signed.WriteString(sshsigMagic)
	writeSSHString(&signed, []byte(namespace))
	writeSSHString(&signed, nil) // reserved
	writeSSHString(&signed, []byte("sha512"))
	writeSSHString(&signed, h[:])

	sig, err := signer.Sign(rand.Reader, signed.Bytes())
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	// Standard SSH signature wire encoding: string(format) || string(blob).
	var sigWire bytes.Buffer
	writeSSHString(&sigWire, []byte(sig.Format))
	writeSSHString(&sigWire, sig.Blob)

	// Outer SSHSIG container.
	var blob bytes.Buffer
	blob.WriteString(sshsigMagic)
	blob.Write([]byte{0, 0, 0, 1}) // SIG_VERSION = 1
	writeSSHString(&blob, signer.PublicKey().Marshal())
	writeSSHString(&blob, []byte(namespace))
	writeSSHString(&blob, nil) // reserved
	writeSSHString(&blob, []byte("sha512"))
	writeSSHString(&blob, sigWire.Bytes())

	armored := pem.EncodeToMemory(&pem.Block{
		Type:  "SSH SIGNATURE",
		Bytes: blob.Bytes(),
	})
	return string(armored), nil
}

// writeSSHString appends an SSH wire string: a uint32 big-endian length prefix
// followed by the raw bytes.
func writeSSHString(buf *bytes.Buffer, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	buf.Write(l[:])
	buf.Write(b)
}
