#!/usr/bin/env bash
# PID 1 inside the enclave. Starts nitriding (which terminates TLS and reverse-
# proxies to our app) and then the signing app itself.
#
# nitriding presents a SELF-SIGNED certificate here (no -acme flag). That means
# clients can't validate it against a public CA — and that's fine: trust comes
# from the NSM attestation (the `attest` step on the client), not from the web
# PKI. To use a real Let's Encrypt certificate instead, add `-acme`, give the
# enclave a real -fqdn and a routable port 443, and run gvproxy on the host so
# nitriding can reach Let's Encrypt for the TLS-ALPN-01 challenge.
set -euo pipefail

FQDN="${ENCLAVE_FQDN:-enclave.example.com}"

# -vsock-ext         : accept external traffic over vsock (bridged from the host)
# -extport 443       : external HTTPS port
# -appwebsrv         : where nitriding forwards decrypted requests (our app)
# -host-proxy-port   : vsock port of the host network proxy (gvproxy) nitriding
#                      uses to bring up its network stack on boot
/nitriding \
    -fqdn "$FQDN" \
    -vsock-ext \
    -extport 443 \
    -host-proxy-port 1024 \
    -appwebsrv http://127.0.0.1:8081 &

# Give nitriding a moment to come up before the app starts serving behind it.
sleep 5

# Replace the shell with the app; when it exits, the enclave shuts down and the
# host's run-enclave.sh restarts it.
exec /secure-git-signer-enclave
