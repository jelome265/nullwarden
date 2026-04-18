#!/usr/bin/env sh
set -eu

# Fuzzing launcher for NullWarden
# Requirements: cargo-fuzz installed

TARGET=${1:-}

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_name> [fuzzer_args...]"
    echo "Available targets:"
    ls crates/nullwarden-fuzz/fuzz_targets/*.rs | xargs -n1 basename | sed 's/\.rs//'
    exit 1
fi

shift 1 || true

echo "Running fuzzer for target: $TARGET..."
cargo +nightly fuzz run "$TARGET" -- -max_total_time=3600 "$@"
