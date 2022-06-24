from typing import Union
from base64 import b64encode, b64decode

from .validator import ensure_type


def get_custom_key(master_pass: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    master_pass = bytes(master_pass, "utf-8")

    # Get custom key for Fernet using user's master password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(master_pass)


def generate_salt() -> bytes:
    from secrets import token_bytes
    return token_bytes(12)


def encrypt_string(master_pass: str, raw_data: str, salt: bytes) -> Union[bytes, None]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    derived_key = get_custom_key(master_pass, salt)

    encrypted_data = AESGCM(derived_key).encrypt(salt, bytes(raw_data, "utf-8"), b"")

    return encrypted_data


def decrypt_string(master_pass: str, encrypted_data: bytes, salt: bytes) -> Union[str, None]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    derived_key = get_custom_key(master_pass, salt)

    decrypted_data = AESGCM(derived_key).decrypt(salt, encrypted_data, b"")

    return str(decrypted_data, "utf-8")


def encrypt_and_encode(master_pass: str, data: str, salt: bytes) -> Union[str,None]:
    if not data:
        return ''

    ensure_type(master_pass, str, "master_pass", "str")
    ensure_type(data, str, "data", "str")
    ensure_type(salt, bytes, "salt", "bytes")

    encrypted_data = encrypt_string(master_pass, data, salt)

    return b64encode(encrypted_data).decode("ascii")


def decode_and_decrypt(master_pass: str, data: str, salt: bytes) -> Union[str,None]:
    if not data:
        return ''

    ensure_type(master_pass, str, "master_pass", "str")
    ensure_type(data, str, "data", "str")
    ensure_type(salt, bytes, "salt", "bytes")

    print(data)

    decrypted_data = decrypt_string(master_pass, b64decode(data), salt)
    return decrypted_data if decrypted_data else ""


if __name__ == "__main__":
    master_pass = input("master password: ")
    user_data = input("Input some data you want to encrypt: ")

    salt = generate_salt()
    print(f"salt: {salt}")

    encrypted_and_encoded_data = encrypt_and_encode(master_pass, user_data, salt)

    print(encrypted_and_encoded_data)
    decrypted_data = decode_and_decrypt(master_pass, encrypted_and_encoded_data, salt)

    print(decrypted_data == user_data)


