# Launching the API on your local computer

You run it in WSL with two terminal windows: one for Vault, one for the app. The app now needs Vault to start, because it gets its JWT secret from there.

## Terminal 1: start Vault and leave it running

vault server -dev -dev-root-token-id=myroot


## Terminal 2: set Vault up, then start the app

cd ~/path/to/DevSecOps-Ubuntu-CI-CD      # your repo folder

 
### 1. tell this terminal where Vault is, and log in as root
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=myroot
 
### 2. put the secret, policy and AppRole into Vault (the script you made)
./scripts/vault-setup.sh
 
### 3. download the app's packages (only needed the first time)
npm install
 
### 4. give the app its Vault login, then start it
export VAULT_ROLE_ID=$(cat ~/.notes-secrets/role_id)
export VAULT_SECRET_ID_FILE=~/.notes-secrets/secret_id


npm start
You should see: listening on 3000