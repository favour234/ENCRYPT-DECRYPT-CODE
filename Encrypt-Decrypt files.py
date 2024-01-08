# Import necessary libraries
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Function to generate RSA key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

# Function to encrypt a file or folder
def encrypt_file(file_path, public_key: rsa.RSAPublicKey, output_path):
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    cipher_text = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_path, 'wb') as file:
        file.write(cipher_text)

# Function to decrypt a file
def decrypt_file(cipher_text_path, private_key, output_path):
    with open(cipher_text_path, 'rb') as file:
        cipher_text = file.read()

    plaintext = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_path, 'wb') as file:
        file.write(plaintext)

# Function to sign a file or folder
def sign_file(file_path, private_key):
    with open(file_path, 'rb') as file:
        data = file.read()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(file_path + '.sig', 'wb') as file:
        file.write(signature)

# Function to verify a signature
def verify_signature(file_path, public_key):
    with open(file_path, 'rb') as file:
        data = file.read()

    with open(file_path + '.sig', 'rb') as file:
        signature = file.read()

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
    except Exception as e:
        print(f"Signature verification failed: {e}")

# Generate key pairs for two users
user1_private_key, user1_public_key = generate_key_pair()
user2_private_key, user2_public_key = generate_key_pair()

# Example usage
file_to_encrypt = 'docs.txt'
encrypted_file_path = 'encrypted_file.enc'
decrypted_file_path = 'decrypted_file.txt'
signature_file_path = 'example.txt.sig'

# Encrypt and Decrypt for User 1
encrypt_file(file_to_encrypt, user1_public_key, encrypted_file_path)
