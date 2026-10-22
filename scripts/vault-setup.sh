#!/bin/bash
# Sets up Vault for the notes app. Needs VAULT_ADDR and VAULT_TOKEN to be set.
set -e

vault kv put -mount=secret notes/app jwt_secret="$(openssl rand -hex 32)"
vault policy write notes-app vault/notes-app.hcl
vault auth enable approle 2>/dev/null || echo "approle already enabled"
vault write auth/approle/role/notes-app token_policies=notes-app

mkdir -p ~/.notes-secrets
vault read -field=role_id auth/approle/role/notes-app/role-id > ~/.notes-secrets/role_id
vault write -f -field=secret_id auth/approle/role/notes-app/secret-id > ~/.notes-secrets/secret_id
chmod 600 ~/.notes-secrets/*

echo "Done. Login details saved in ~/.notes-secrets/"
