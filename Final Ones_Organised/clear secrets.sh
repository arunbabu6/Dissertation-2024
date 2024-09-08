# List all imagehash secrets
secrets=$(aws secretsmanager list-secrets --query "SecretList[?contains(Name, 'imagehash')].Name" --output text)

# Loop through each secret and delete it
for secret in $secrets; do
    aws secretsmanager delete-secret --secret-id $secret --force-delete-without-recovery
done
