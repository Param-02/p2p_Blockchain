# generate_keys.py
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys(username):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize and save private key
    private_key_filename = f"{username}_private_key.pem"
    with open(private_key_filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Serialize and save public key
    public_key = private_key.public_key()
    public_key_filename = f"{username}_public_key.pem"
    with open(public_key_filename, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"{username.capitalize()}'s key pair generated and saved as '{private_key_filename}' and '{public_key_filename}'.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python generate_keys.py <username>")
        sys.exit(1)
    
    username = sys.argv[1].lower()
    generate_keys(username)
