from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_default_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key


# Generate the default key pair
server_private_key, server_public_key = generate_default_key_pair()

# Save the private key to a file
with open("server_private_key.pem", "wb") as file:
    private_key_bytes = server_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    file.write(private_key_bytes)

# Save the public key to a file
with open("server_public_key.pem", "wb") as file:
    public_key_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    file.write(public_key_bytes)
