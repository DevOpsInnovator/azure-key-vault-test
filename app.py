import os
import streamlit as st
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import yaml


def get_keyvault_url():
    # Try environment variable first
    keyvault_url = os.getenv("KEY_VAULT_URL")
    if keyvault_url:
        return keyvault_url

    # Fallback to config.yaml
    try:
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
            return config["keyvault_url"]
    except Exception as e:
        st.error(f"Configuration error: {str(e)}")
        st.stop()


def main():
    st.title("Azure Key Vault Secrets Viewer")

    keyvault_url = get_keyvault_url()

    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=keyvault_url, credential=credential)

        secrets_list = []
        for secret_properties in client.list_properties_of_secrets():
            if secret_properties.enabled:
                secret = client.get_secret(secret_properties.name)
                secrets_list.append({
                    "Name": secret.name,
                    "Value": secret.value
                })

        if secrets_list:
            st.table(secrets_list)
        else:
            st.warning("No enabled secrets found in the Key Vault")
    except Exception as e:
        st.error(f"Error accessing Key Vault: {str(e)}")


if __name__ == "__main__":
    main()
