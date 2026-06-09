#!/usr/bin/env bash
# build-eif.sh — build the enclave image, package it into an EIF with nitro-cli,
# and capture the PCR0 measurement. Run this on an Amazon Linux 2023 host with
# Docker and the aws-nitro-enclaves-cli installed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE="secure-git-signer-enclave:latest"
EIF_FILE="$REPO_ROOT/build/app.eif"
PCR0_FILE="$REPO_ROOT/pcr0.txt"

echo "[build-eif] Building enclave image..."
docker build -f "$REPO_ROOT/build/Dockerfile.enclave" -t "$IMAGE" "$REPO_ROOT"

echo "[build-eif] Packaging EIF with nitro-cli..."
MEASUREMENTS="$(nitro-cli build-enclave --docker-uri "$IMAGE" --output-file "$EIF_FILE")"
echo "$MEASUREMENTS"

PCR0="$(echo "$MEASUREMENTS" | grep -oP '"PCR0"\s*:\s*"\K[^"]+')"
if [ -z "$PCR0" ]; then
    echo "[build-eif] ERROR: could not extract PCR0" >&2
    exit 1
fi

echo "$PCR0" > "$PCR0_FILE"
echo "[build-eif] Done."
echo "[build-eif]   EIF:  $EIF_FILE"
echo "[build-eif]   PCR0: $PCR0  (written to $PCR0_FILE)"
