import base64
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- 1. RSA KEY MANAGEMENT ---

def generate_rsa_key_pair():
    """Generates a private and public RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    # Serialize Private Key to PEM format (User must store this securely)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize Public Key to PEM format (Stored in the database)
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_private.decode('utf-8'), pem_public.decode('utf-8')

# --- 2. HYBRID ENCRYPTION (AES-GCM + RSA) ---

def encrypt_message(message: str, recipient_public_key_pem: str):
    """
    Encrypts a message using AES-GCM for content and RSA for the AES key.
    Returns: (nonce_b64, combined_body_json)
    """
    # Generate a random 256-bit AES key
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12) # Standard GCM nonce size
    
    # Encrypt the message body with AES
    data = message.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
    
    # Encrypt the AES key with Recipient's RSA Public Key (OAEP Padding)
    public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode('utf-8'))
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Encode values to Base64 for database storage
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')
    enc_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
    
    # Combine ciphertext and encrypted AES key into a single JSON body
    combined_body = json.dumps({
        "content": ciphertext_b64,
        "key": enc_aes_key_b64
    })
    
    return nonce_b64, combined_body

# --- 3. RSA DIGITAL SIGNATURES (RSA-PSS) ---

def sign_data(data: str, private_key_pem: str) -> str:
    """Signs data using the Sender's RSA Private Key."""
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data: str, signature_b64: str, public_key_pem: str) -> bool:
    """Verifies the RSA-PSS signature using the Sender's Public Key."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False