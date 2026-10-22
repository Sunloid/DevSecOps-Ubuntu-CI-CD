#!/usr/bin/env bash
set -euo pipefail
: "${VAULT_ADDR:?VAULT_ADDR is not set}"
: "${VAULT_TOKEN:?VAULT_TOKEN is not set}"

JWT_SECRET="$(vault kv get -field=jwt_secret -mount=secret notes/app)"
export JWT_SECRET

exec "$@"
