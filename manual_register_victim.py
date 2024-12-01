# register_victim.py
import requests
import json
from cryptography.hazmat.primitives import serialization

# Configuration
TARGET_NODE = 'http://172.16.83.23:5000/register_with_keys'  # Update as needed

# Load keys
with open('victim_public_key.pem', 'r') as f:
    public_key_pem = f.read()

with open('victim_private_key.pem', 'rb') as f:
    private_key_pem = f.read()

# Encrypt the private key with a password
password = 'victim_password'  # Replace with your desired password
password_bytes = password.encode('utf-8')

private_key = serialization.load_pem_private_key(
    private_key_pem,
    password=None,  # Assuming the private key is not already encrypted
)

encrypted_private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
).decode('utf-8')

# Prepare payload
payload = {
    "username": "victim",
    "password": password,  # Include the password
    "balance": "100",
    "public_key_pem": public_key_pem,
    "encrypted_private_key_pem": encrypted_private_key_pem
}

# Send the request
response = requests.post(TARGET_NODE, json=payload)

# Check response
if response.status_code == 200:
    print("Victim registered successfully.")
else:
    print(f"Failed to register victim: {response.json().get('error')}")
