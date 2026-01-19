import os
import argon2
import base64

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Konfiguracja argon2
ph = argon2.PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
# 2 iteracje algorytmu argon2
# 65536 - ilość pamięci używanych przez algorytm
# 2 - ilość wątków używanych przez algorytm
# 32 bajty - długość hashu
# 16 bajtów - długość soli

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(hash: str, password: str) -> bool:
    try:
        ph.verify(hash, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False

# Generowanie pary kluczy RSA 2048-bit (lucz prywatny szyfrowany hasłem)
def generate_key_pair(password: str):

    private_key = rsa.generate_private_key(
        #standardowy wykładnik publiczny e
        public_exponent=65537,
        # długość klucza RSA (n = p * q)
        key_size=2048
    )
    
    # Szyfrowanie klucza prywatnego hasłem użytkownika
    encrypted_private_pem = private_key.private_bytes(
        # Zapisujemy jako PEM (Base64 + nagłówki tekstowe)
        encoding=serialization.Encoding.PEM,
        # Używamy standardowego formatu dla klucza prywatnego
        format=serialization.PrivateFormat.PKCS8,
        # Szyfrowanie hasłem za pomocą AES-256 i PBKDF2 (domyślnie), informacja zapisana w PEM'ie
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()) # zamieniamy hasło na bajty
    )
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        # Używamy standardowego formatu dla klucza publicznego
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return encrypted_private_pem, public_pem

# Odszyfrowanie klucza prywatnego
def decrypt_private_key(encrypted_pem_data: bytes, password: str):

    try:
        private_key = serialization.load_pem_private_key(
            encrypted_pem_data,
            password=password.encode(),
        )
        return private_key
    except Exception:
        return None

# Szyfrowanie sekretu TOTP użytkownika hasłem (PBKDF2 + AES-128 CBC i HMAC-SHA256 Fernet)
def encrypt_totp(data: str, password: str) -> bytes:

    salt = os.urandom(16)
    
    # Wyprowadzenie klucza z hasła i soli
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    # Wynikowo 32 bajty (wymóg biblioteki Fernet)
    
    # Wyprowadzenie klucza zakodowane w base64 (wymóg biblioteki Fernet)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    # Szyfrowanie
    f = Fernet(key)
    token = f.encrypt(data.encode())
    
    # salt (16 bajtów) + token
    return salt + token

# Odszyfrowanie sekretu TOTP 
def decrypt_totp(encrypted_data: bytes, password: str) -> str:

    # Wyciągnięcie danych
    salt = encrypted_data[:16]
    token = encrypted_data[16:]
    
    # Wyprowadzenie klucza (tak jak przy szyfrowaniu)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    # Odszyfrowanie
    f = Fernet(key)
    try:
        decrypted_bytes = f.decrypt(token)
        return decrypted_bytes.decode('utf-8')
    except Exception:
        return None

# Szyfrowanie tekstu wiadomosci i załączników za pomocą AES-256 GCM
def encrypt_aes_gcm(session_key: bytes,plaintext: bytes):

    #przekazany klucz sesyjny ma długość 32 bajtów - 256-bit

    nonce = os.urandom(12) # 96-bit nonce (number generated once) dla GCM

    # obiekt szyfrowania
    cipher = Cipher( algorithms.AES(session_key), modes.GCM(nonce), backend=default_backend() )
    encryptor = cipher.encryptor()
    
    # szyfrowanie, najpierw dane (plaintext), następnie kończymy i obliczamy tag (finalize)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext, nonce, encryptor.tag, session_key

# Odszyfrowanie tekstu wiadomosci i załączników za pomocą AES-256 GCM
def decrypt_aes_gcm(session_key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:

    cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    return decryptor.update(ciphertext) + decryptor.finalize()

# Szyfrowanie klucza sesyjnego za pomocą RSA (OAEP + MGF1 + SHA256)
def encrypt_rsa(public_key_pem: str, data: bytes) -> bytes:

    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    
    encrypted = public_key.encrypt(
        data,
        # algorytm dopełnienia OAEP
        padding.OAEP(
            # Mask Generation Function - MGF1 (z SHA256 jako silnik mieszajacy)
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            # Algorytm mieszania danych (SHA256)
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Oszyfrowywanie klucza sesyjnego za pomocą RSA (OAEP + MGF1 + SHA256)
def decrypt_rsa(private_key, ciphertext: bytes) -> bytes:

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# Podpisanie zaszyfrowanych danych za pomocą RSA (PSS + MGF1 + SHA256)
def sign_rsa(private_key, data: bytes) -> bytes:

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Weryfikacja podpisu/sygnatury zaszyfrowanych danych za pomocą RSA (PSS + MGF1 + SHA256)
def verify_signature_rsa(public_key_pem: str, data: bytes, signature: bytes) -> bool:

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False