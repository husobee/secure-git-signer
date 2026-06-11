#!/usr/bin/env bash
# run-enclave.sh — start the enclave on a Nitro-enabled host and keep it running.
#
# This is dramatically simpler than a production enclave runner because the app
# is self-contained: it generates its own signing key on boot and talks to no
# AWS services, so there is no bootstrap config to push in, no KMS/DynamoDB vsock
# proxies, and no IAM credential-refresh loop. All that's left is:
#   1. gvproxy   — the host-side network proxy nitriding uses to bring up its
#                  network stack inside the enclave (see note below).
#   2. a vsock bridge so external TCP:443 reaches nitriding inside the enclave.
#   3. run the enclave and restart it if it dies.
set -euo pipefail

CPU_COUNT="${ENCLAVE_CPU_COUNT:-2}"
MEMORY_MIB="${ENCLAVE_MEMORY_MIB:-1024}"
CID="${ENCLAVE_CID:-16}"
EIF_PATH="${EIF_PATH:-/opt/secure-git-signer/app.eif}"
GVPROXY_BIN="${GVPROXY_BIN:-/opt/secure-git-signer/gvproxy}"
GVPROXY_PORT=1024

log() { echo "[run-enclave] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

terminate_all() {
    nitro-cli describe-enclaves | jq -r '.[].EnclaveID' 2>/dev/null | while read -r id; do
        log "Terminating enclave $id"
        nitro-cli terminate-enclave --enclave-id "$id" || true
    done
}

# nitriding sets up an internal network stack over vsock on boot and uses gvproxy
# on the host as its L2 peer. We don't need outbound internet for the signing
# flow (TLS is self-signed, no ACME), but nitriding still expects this proxy to
# be present while it initialises. If your nitriding build boots without it, you
# can drop this.
start_gvproxy() {
    log "Starting gvproxy on vsock:$GVPROXY_PORT"
    ( while true; do "$GVPROXY_BIN" -listen "vsock://:$GVPROXY_PORT" || true; sleep 2; done ) &
}

# Bridge external traffic into the enclave: host TCP:443 -> vsock:CID:443, where
# nitriding (started with -vsock-ext -extport 443) is listening.
start_inbound_bridge() {
    log "Bridging TCP:443 -> vsock:$CID:443"
    ( while true; do socat TCP4-LISTEN:443,fork,reuseaddr "VSOCK-CONNECT:$CID:443" || true; sleep 2; done ) &
}

start_enclave() {
    log "Starting enclave (cpu=$CPU_COUNT memory=${MEMORY_MIB}MiB cid=$CID eif=$EIF_PATH)"
    nitro-cli run-enclave \
        --cpu-count "$CPU_COUNT" \
        --memory "$MEMORY_MIB" \
        --eif-path "$EIF_PATH" \
        --enclave-cid "$CID"
}

cleanup() {
    log "Shutdown signal — terminating enclave"
    terminate_all
    exit 0
}
trap cleanup SIGTERM SIGINT

terminate_all
start_gvproxy
start_inbound_bridge
start_enclave

# Health loop: restart the enclave if it exits unexpectedly.
while true; do
    sleep 10
    if ! nitro-cli describe-enclaves | jq -e '.[0]' > /dev/null 2>&1; then
        log "Enclave not running — restarting"
        start_enclave
    fi
done
