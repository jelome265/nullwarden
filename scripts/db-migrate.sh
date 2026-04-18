#!/usr/bin/env sh
set -eu

# Database migration script for NullWarden Server
# Requirements: sqlx-cli installed, DATABASE_URL env var set

if [ -z "${DATABASE_URL:-}" ]; then
    if [ -f .env ]; then
        export $(grep -v '^#' .env | xargs)
    else
        echo "Error: DATABASE_URL not set and .env file not found."
        exit 1
    fi
fi

echo "Running database migrations..."
sqlx migrate run --source crates/nullwarden-server/migrations

echo "Migrations complete."
