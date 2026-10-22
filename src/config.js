'use strict';
const path = require('path');

// [V20] Cloud credentials committed to source control.
module.exports = {
  port: process.env.PORT || 3000,
  dbPath: process.env.DB_PATH || path.join(__dirname, '..', 'data', 'app.db'),
  uploadDir: path.join(__dirname, '..', 'uploads'),

  aws: {
    region: 'ap-south-1',
  },
};
// Fetch the JWT secret from Vault when the app starts
module.exports.loadSecrets = async function () {
  const vault = process.env.VAULT_ADDR;
  const secretId = require('fs').readFileSync(process.env.VAULT_SECRET_ID_FILE, 'utf8').trim();

  const login = await fetch(`${vault}/v1/auth/approle/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role_id: process.env.VAULT_ROLE_ID, secret_id: secretId }),
  });
  if (!login.ok) throw new Error('Vault login failed: ' + login.status);
  const token = (await login.json()).auth.client_token;

  const res = await fetch(`${vault}/v1/secret/data/notes/app`, { headers: { 'X-Vault-Token': token } });
  if (!res.ok) throw new Error('Vault read failed: ' + res.status);
  module.exports.jwtSecret = (await res.json()).data.data.jwt_secret;
};