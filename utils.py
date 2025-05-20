from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives import padding as sym_padding

def generate_rsa_keys():
    """Génère une paire de clés RSA"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_rsa_keys(user_id, private_key, public_key):
    """Sauvegarde les clés RSA d'un utilisateur"""
    if not os.path.exists('keys'):
        os.makedirs('keys')
    
    # Sauvegarder la clé privée
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f'keys/user_{user_id}_private.pem', 'wb') as f:
        f.write(private_pem)
    
    # Sauvegarder la clé publique
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f'keys/user_{user_id}_public.pem', 'wb') as f:
        f.write(public_pem)

def get_user_public_key(user_id):
    """Récupère la clé publique d'un utilisateur"""
    try:
        with open(f'keys/user_{user_id}_public.pem', 'rb') as f:
            return serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
    except:
        return None

def get_user_private_key(user_id):
    """Récupère la clé privée d'un utilisateur"""
    try:
        with open(f'keys/user_{user_id}_private.pem', 'rb') as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    except:
        return None

def generate_random_aes_key():
    """Génère une clé AES aléatoire"""
    return os.urandom(32)  # 256 bits

def generate_random_iv():
    """Génère un vecteur d'initialisation aléatoire pour AES"""
    return os.urandom(16)  # 128 bits

def encrypt_with_aes(message, key, iv):
    """Chiffre un message avec AES"""
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Padding du message pour avoir une longueur multiple de 16
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    
    # Chiffrement
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(encrypted_data).decode()

def decrypt_with_aes(encrypted_message, key, iv):
    """Déchiffre un message avec AES"""
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Déchiffrement
    encrypted_data = base64.b64decode(encrypted_message)
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Suppression du padding
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data.decode()

def encrypt_with_rsa(data, public_key):
    """Chiffre des données avec une clé publique RSA"""
    encrypted = public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def decrypt_with_rsa(encrypted_data, private_key):
    """Déchiffre des données avec une clé privée RSA"""
    encrypted = base64.b64decode(encrypted_data)
    decrypted = private_key.decrypt(
        encrypted,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def generate_hmac(message, key):
    """Génère un HMAC SHA-256 pour le message donné avec la clé donnée."""
    h = hmac.new(key, message.encode(), hashlib.sha256)
    return base64.b64encode(h.digest()).decode()

def sign_message(message, private_key):
    """Signe un message avec une clé privée RSA (SHA-256)."""
    signature = private_key.sign(
        message.encode(),
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_signature(message, signature, public_key):
    """Vérifie la signature d'un message avec une clé publique RSA (SHA-256)."""
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def verify_hmac(message, hmac_to_check, key):
    """Vérifie qu'un HMAC correspond au message et à la clé donnés (SHA-256)."""
    import hmac as hmac_lib
    import hashlib
    import base64
    expected_hmac = hmac_lib.new(key, message.encode(), hashlib.sha256)
    expected_hmac_b64 = base64.b64encode(expected_hmac.digest()).decode()
    return hmac_to_check == expected_hmac_b64
