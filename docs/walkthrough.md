# Walkthrough

End-to-end: build the enclave, deploy it, point git at it, and verify a signed
commit. Three machines/roles are involved:

- **Your laptop** — builds the client shim, configures git, makes commits.
- **A build host** — Amazon Linux 2023 with Docker + `nitro-cli`, used once to
  produce the EIF. (Can be the enclave host itself, or any AL2023 box.)
- **The enclave host** — the EC2 instance CDK provisions; runs the enclave.

---

## 1. Run the tests (optional, on your laptop)

```bash
make test
```

The enclave test signs a payload and verifies it with the real
`ssh-keygen -Y verify`, proving git will accept the enclave's signatures.

## 2. Build the EIF and capture PCR0 (on the build host)

Requires Docker and `aws-nitro-enclaves-cli`:

```bash
make eif
# → build/app.eif
# → pcr0.txt   (the measurement of this exact image)
```

PCR0 is the SHA-384 hash of the enclave image. It's what the client checks (via
attestation) to know *which code* is holding the signing key. Change a byte of
the app and PCR0 changes.

## 3. Deploy the host (from your laptop)

```bash
cd iac
npm install
npx cdk bootstrap      # first time in this account/region only
npx cdk deploy
```

Outputs include:

- `ArtifactBucket` — where the host expects the EIF.
- `UploadEifCommand` — the exact `aws s3 cp` line for the next step.
- `EnclaveUrl` — `https://<public-ip>`.
- `InstanceId` — for opening a shell with SSM.

## 4. Upload the EIF

```bash
aws s3 cp build/app.eif s3://<ArtifactBucket>/app.eif
```

The host's `secure-git-signer.service` retries until this object exists, then
pulls it and launches the enclave. To watch progress:

```bash
aws ssm start-session --target <InstanceId>
sudo journalctl -u secure-git-signer -f
sudo nitro-cli describe-enclaves
```

## 5. Trust the enclave (on your laptop)

```bash
make signer        # builds ./client/git-enclave-signer
export ENCLAVE_URL=https://<public-ip>

./client/git-enclave-signer attest "$ENCLAVE_URL"
```

This fetches a fresh attestation document, verifies it against the AWS Nitro
root, checks the nonce and that the document binds the public key, then prints:

```
✓ enclave attestation verified against the AWS Nitro root
  module: i-0abc…-enc0123…
  PCR0:   1f2e…
Trusted signing key (use for allowed_signers / user.signingkey):
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… secure-git-signer-enclave
```

Save that key:

```bash
./client/git-enclave-signer attest "$ENCLAVE_URL" | tail -1 > ~/.config/git/enclave-signer.pub
```

> If `attest` reports an **INSECURE dev-mode attestation**, the enclave is
> running without a real NSM device — you're pointing at a local dev process,
> not a deployed enclave. Don't trust that key.

## 6. Point git at the enclave

```bash
git config gpg.format ssh
git config gpg.ssh.program "$(pwd)/client/git-enclave-signer"
git config user.signingkey ~/.config/git/enclave-signer.pub
git config commit.gpgsign true
# ENCLAVE_URL must be set in the environment git runs in
```

## 7. Sign and verify

```bash
git commit -S -m "signed in an enclave"
```

To verify, add the key to an allowed_signers file and let git check it:

```bash
printf '%s %s\n' "you@example.com" "$(cat ~/.config/git/enclave-signer.pub)" \
  > ~/.config/git/allowed_signers
git config gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers

git log --show-signature -1
# Good "git" signature with ED25519 key SHA256:…
```

The private key that produced that signature exists only inside the enclave.

---

## Going further

- **Persistent key.** Swap the boot-time keygen for a KMS-wrapped key whose
  release is gated on PCR0, so the same identity survives restarts and only this
  exact enclave image can decrypt it.
- **Real certificate.** Add nitriding's `-acme`, a public DNS name, and a
  raw-TCP load balancer on 443 so the enclave gets a Let's Encrypt cert and the
  browser padlock — instead of self-signed-plus-attestation.
- **Pinned, reproducible builds.** Pin every base image in
  `build/Dockerfile.enclave` by digest and vendor Go deps, so PCR0 is stable
  across rebuilds and others can reproduce it.
