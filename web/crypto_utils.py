# web/crypto_utils.py
import argon2
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Konfiguracja Argon2 (twarde limity dla bezpieczeństwa)
ph = argon2.PasswordHasher(
    time_cost=2, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16
)

def hash_password(password: str) -> str:
    """Tworzy bezpieczny hash hasła."""
    return ph.hash(password)

def verify_password(hash: str, password: str) -> bool:
    """Sprawdza czy hasło pasuje do hasha."""
    try:
        ph.verify(hash, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False

def generate_key_pair(password: str):
    """
    Generuje parę kluczy RSA 2048-bit.
    Klucz prywatny jest SZYFROWANY hasłem użytkownika (AES-256).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Szyfrowanie klucza prywatnego hasłem użytkownika
    encrypted_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return encrypted_private_pem, public_pem