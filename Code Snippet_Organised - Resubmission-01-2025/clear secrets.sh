# List all secrets that contain "ImageHash"
secrets=$(aws secretsmanager list-secrets --query "SecretList[?contains(Name, 'ImageHash')].Name" --output text)

# Check if any secrets were found
if [ -z "$secrets" ]; then
    echo "No secrets found matching 'ImageHash'"
    exit 1
fi

# Loop through each secret and delete it
for secret in $secrets; do
    echo "Deleting secret: $secret"
    aws secretsmanager delete-secret --secret-id "$secret" --force-delete-without-recovery
done
