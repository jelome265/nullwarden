#!/usr/bin/env sh
set -eu

# Enterprise-level release signing script
# Requirements: minisign installed, MINISIGN_SECRET_KEY env var set

if [ -z "${MINISIGN_SECRET_KEY:-}" ]; then
    echo "Error: MINISIGN_SECRET_KEY environment variable is not set."
    exit 1
fi

BIN_DIR="target/release"
CLI_BIN="$BIN_DIR/nullwarden-cli"

if [ ! -f "$CLI_BIN" ]; then
    echo "Error: CLI binary not found at $CLI_BIN. Run cargo build --release first."
    exit 1
fi

echo "Signing $CLI_BIN..."

# Use minisign to sign the binary
# -S: sign
# -s: secret key file (using /dev/stdin to avoid writing secret to disk)
# -m: message (file to sign)
# -t: comment
echo "$MINISIGN_SECRET_KEY" | minisign -S -s /dev/stdin -m "$CLI_BIN" -t "NullWarden Official Release"

echo "Signing complete. Signature file: $CLI_BIN.minisig"
