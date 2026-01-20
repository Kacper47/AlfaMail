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
    
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_private.decode('utf-8'), pem_public.decode('utf-8')

# --- 2. HYBRID ENCRYPTION (AES-GCM + RSA) ---

def encrypt_message(message: str, recipient_public_key_pem: str):
    """Encrypts content using AES-GCM and the AES key with RSA."""
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    
    data = message.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
    
    public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode('utf-8'))
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return base64.b64encode(nonce).decode('utf-8'), json.dumps({
        "content": base64.b64encode(ciphertext).decode('utf-8'),
        "key": base64.b64encode(encrypted_aes_key).decode('utf-8')
    })

def decrypt_message(combined_body_json: str, nonce_b64: str, private_key_pem: str):
    """Decrypts a hybrid-encrypted message using RSA and AES-GCM."""
    try:
        body = json.loads(combined_body_json)
        ciphertext = base64.b64decode(body["content"])
        encrypted_aes_key = base64.b64decode(body["key"])
        nonce = base64.b64decode(nonce_b64)

        private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None).decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

# --- 3. RSA DIGITAL SIGNATURES ---

def sign_data(data: str, private_key_pem: str) -> str:
    """Signs data using the Sender's RSA Private Key."""
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data: str, signature_b64: str, public_key_pem: str) -> bool:
    """Verifies RSA-PSS signature."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        public_key.verify(
            base64.b64decode(signature_b64),
            data.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False