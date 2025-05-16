import streamlit as st
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import re

# Streamlit app title
st.title("Azure Key Vault Connection Tester")

# Instructions
st.markdown("""
This app tests connectivity to an Azure Key Vault and retrieves a specified secret.
Ensure you have the necessary permissions and Azure credentials configured.
""")

# Input fields
key_vault_name = st.text_input(
    "Key Vault Name", placeholder="e.g., mykeyvault")
secret_name = st.text_input("Secret Name to Test",
                            placeholder="e.g., my-secret")

# Button to test connection
if st.button("Test Connection"):
    if not key_vault_name or not secret_name:
        st.error("Please provide both Key Vault name and secret name.")
    else:
        # Validate Key Vault name (basic regex for alphanumeric and hyphens)
        if not re.match(r"^[a-zA-Z0-9-]{3,24}$", key_vault_name):
            st.error(
                "Invalid Key Vault name. Use 3-24 alphanumeric characters or hyphens.")
        else:
            try:
                # Construct Key Vault URL
                vault_url = f"https://{key_vault_name}.vault.azure.net"

                # Authenticate using DefaultAzureCredential
                credential = DefaultAzureCredential()

                # Create SecretClient
                secret_client = SecretClient(
                    vault_url=vault_url, credential=credential)

                # Test connection by retrieving the secret
                st.write(
                    "Attempting to connect to Key Vault and retrieve secret...")
                secret = secret_client.get_secret(secret_name)

                # Display success message and secret details
                st.success(
                    f"Successfully connected to Key Vault: {key_vault_name}")
                st.write(f"Secret Name: {secret.name}")
                st.write(f"Secret Value: {secret.value}")
                st.write(f"Last Updated: {secret.properties.updated_on}")

            except Exception as e:
                # Handle errors (e.g., authentication failure, secret not found)
                st.error(
                    f"Failed to connect to Key Vault or retrieve secret. Error: {str(e)}")
                st.markdown("""
                **Common issues and fixes:**
                - **Authentication error**: Ensure your Azure credentials are configured (e.g., via `az login`, environment variables, or managed identity).
                - **Key Vault not found**: Verify the Key Vault name and your network connectivity.
                - **Secret not found**: Check that the secret exists in the Key Vault.
                - **Permissions**: Ensure your account has 'Get' permissions for secrets in the Key Vault's access policies.
                """)

# Footer
st.markdown("---")
st.write("Note: This app uses `DefaultAzureCredential` for authentication. Ensure your environment is set up with valid Azure credentials.")
