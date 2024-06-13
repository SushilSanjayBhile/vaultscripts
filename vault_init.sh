#!/bin/bash

VAULT_POLICIES=vault/policies
VAULT_TOKENS=vault/tokens
REGION="us-west-2"  # Replace with your desired AWS region
SECRET_PREFIX="VaultSecret-sg-"

# Check if directory exists
if [ ! -d "$VAULT_POLICIES" ]; then
    echo "Directory $VAULT_POLICIES does not exist. Creating it..."
    sudo mkdir -p "$VAULT_POLICIES"
    echo "Directory $VAULT_POLICIES created."
else
    echo "Directory $VAULT_POLICIES already exists."
fi

# Check if directory exists
if [ ! -d "$VAULT_TOKENS" ]; then
    echo "Directory $VAULT_TOKENS does not exist. Creating it..."
    sudo mkdir -p "$VAULT_TOKENS"
    echo "Directory $VAULT_TOKENS created."
else
    echo "Directory $VAULT_TOKENS already exists."
fi

directory=$VAULT_TOKENS/drio-controller
# Check if directory exists
if [ ! -d "$directory" ]; then
    echo "Directory $directory does not exist. Creating it..."
    sudo mkdir -p "$directory"
    echo "Directory $directory created."
else
    echo "Directory $directory already exists."
fi

# Check if VAULT_ADDR environment variable is set
if [[ -z "${VAULT_ADDR}" ]]; then
  echo "VAULT_ADDR environment variable is not set."
  exit 1
else
  echo "VAULT_ADDR is set to ${VAULT_ADDR}."
fi

while true; do
    # Get the seal status
    sealstatus=$(curl -k ${VAULT_ADDR}/v1/sys/seal-status)

    # Check if the Vault is initialized
    initialized=$(echo $sealstatus | jq -r ".initialized")
    
    # Check if the Vault is sealed
    sealed=$(echo $sealstatus | jq -r ".sealed")

    echo "Vault initialized status ${initialized} and seal status ${sealed}"

    # If Vault is initialized and not sealed, break the loop
    if [[ "$initialized" == "true" && "$sealed" == "false" ]]; then
        echo "Vault is initialized and unsealed."
        break
    fi

    # Wait for 10 seconds before checking again
    echo "Vault is either not initialized or sealed. Checking again in 10 seconds..."
    sleep 10
done

# Fetch secrets list from Secrets Manager
secrets=$(aws secretsmanager list-secrets --region $REGION)

# Extract secrets with prefix "VaultSecret-sg-" and fetch their values
filtered_secrets=$(echo "$secrets" | jq -r '.SecretList[] | select(.Name | startswith("'"$SECRET_PREFIX"'")) | .Name')

# Output the secret names and their values
echo "Secrets with prefix '$SECRET_PREFIX':"
for secret_name in $filtered_secrets; do
    echo "Secret Name: $secret_name"
    secret_value=$(aws secretsmanager get-secret-value --region $REGION --secret-id $secret_name --query 'SecretString' --output text)
    
    # Extract Initial Root Token
    initial_root_token=$(echo "$secret_value" | grep -o 'Initial Root Token: .*' | sed 's/Initial Root Token: //')
    
    echo "Initial Root Token: $initial_root_token"
    echo "==============================="
done

export VAULT_TOKEN=$initial_root_token

echo "Enabling secrets"
vault secrets enable -version=2 -path=drio-controller/ops kv
vault secrets enable -version=2 -path=drio-controller/user kv
vault secrets enable -version=2 -path=drio-controller/ddx kv

echo "Creating configdb password"
vault kv put drio-controller/ops/configdb password=$(openssl rand -hex 12)

echo "Creating cache password"
vault kv put drio-controller/ops/cache password=$(openssl rand -hex 12)

echo "Creating controller admin password"
vault kv put drio-controller/ops/saas-admin@drio.ai password=$(openssl rand -hex 12)

echo "Creating secret key to secure JWT tokens"
vault kv put drio-controller/ops/saas-jwtkey key=$(openssl rand -hex 32)

# Add multiple versions of opsuser password. Will be used for testing
echo "Setting test password"
vault kv put drio-controller/ops/opsuser password=$(openssl rand -hex 12)
vault kv put drio-controller/ops/opsuser password=$(openssl rand -hex 12)
vault kv delete -mount drio-controller/ops opsuser
vault kv put drio-controller/ops/opsuser password=$(openssl rand -hex 12)


echo "Attaching policy"
vault policy write drio-controller-policy ${VAULT_POLICIES}/drio-controller-policy.json

echo "Enabling approle"
curl --header "X-Vault-Token: ${VAULT_TOKEN}" --request POST --data '{"type": "approle"}' ${VAULT_ADDR}/v1/sys/auth/approle

echo "Creating drio-controller-role approle role and attaching drio-controller-policy to it"
curl --header "X-Vault-Token: ${VAULT_TOKEN}" --request POST --data '{"policies": "drio-controller-policy"}' ${VAULT_ADDR}/v1/auth/approle/role/drio-controller-role

echo "Extracting approle role id for drio-controller-role"
approle_id_info=$(curl --header "X-Vault-Token: ${VAULT_TOKEN}" ${VAULT_ADDR}/v1/auth/approle/role/drio-controller-role/role-id)
approle_id=$(echo ${approle_id_info} | jq -r ".data.role_id")

echo "Extracting approle secret id for drio-controller-role"
approle_secret_id_info=$(curl --header "X-Vault-Token: ${VAULT_TOKEN}"  --request POST ${VAULT_ADDR}/v1/auth/approle/role/drio-controller-role/secret-id)
echo "approle_secret_id_info: ${approle_secret_id_info}"

approle_secret_id=$(echo ${approle_secret_id_info} | jq -r ".data.secret_id")
echo "approle_secret_id: ${approle_secret_id}"

echo "DRIO_VAULT_ROLE_ID=${approle_id}" | sudo tee ${VAULT_TOKENS}/drio-controller/drio-controller-role.env > /dev/null
echo "DRIO_VAULT_SECRET_ID=${approle_secret_id}" | sudo tee ${VAULT_TOKENS}/drio-controller/drio-controller-role.env > /dev/null
echo "Vault successfully initialized"
