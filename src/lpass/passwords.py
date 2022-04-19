from sys import stderr
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from secrets import choice
from typing import List
import base64
import string

from .validator import ensure_type


def __get_custom_fernet_object(master_password: str, salt: bytes) -> Fernet:
    master_password = bytes(master_password, "utf-8")

    # Get custom key for Fernet using user's masterpassword
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password))

    return Fernet(key)


def encrypt_password(master_password: str, raw_password: str, salt: bytes) -> bytes | None:
    try:
        ensure_type(master_password, str, "master_password", "str")
        ensure_type(raw_password, str, "raw_password", "str")
        ensure_type(salt, bytes,  "salt", "bytes")

        # Make sure that parameters are not empty
        if not master_password:
            raise ValueError("Paramter 'master_password' cannot be empty")
        if not raw_password:
            raise ValueError("Paramter 'raw_password' cannot be empty")
        if not salt:
            raise ValueError("Parameter 'salt' cannot be empty")

        fernet_object: Fernet = __get_custom_fernet_object(master_password, salt)
        password_bytes: bytes = bytes(raw_password, "utf-8")
        encryptedPassword = fernet_object.encrypt(password_bytes)

        return encryptedPassword
    except Exception as e:
        print("There was an error encrypting the password:", file=stderr)
        print(e, file=stderr)
        return None


def decrypt_password(master_password: str, encrypted_password: bytes, salt: bytes) -> str | None:
    try:
        ensure_type(master_password, str, "master_password", "str")
        ensure_type(encrypted_password, bytes, "encrypted_password", "bytes")
        ensure_type(salt, bytes, "salt", "bytes")

        # Make sure that parameters are not empty
        if not master_password:
            raise ValueError("Paramter 'master_password' cannot be empty")
        if not encrypted_password:
            raise ValueError("Paramter 'encrypted_password' cannot be empty")
        if not salt:
            raise ValueError("Parameter 'salt' cannot be empty")

        fernet_object: Fernet = __get_custom_fernet_object(master_password, salt)
        password_bytes: bytes = fernet_object.decrypt(encrypted_password)
        raw_password: str = str(password_bytes, "utf-8")

        return raw_password
    except Exception as e:
        print("There was an error decrypting the password:", file=stderr)
        print(e, file=stderr)


def generate_password(length: int, uppercase: bool, lowercase: bool, numbers: bool, specials: bool) -> str | None:
    # Exception handling
    ensure_type(int, length, int,  "length", "int")
    ensure_type(uppercase, bool, "uppercase", "bool")
    ensure_type(lowercase, bool, "lowercase", "bool")
    ensure_type(numbers, bool, "numbers", "bool")
    ensure_type(specials, bool, "specials", "bool")

    if uppercase == lowercase == numbers == specials == False:
        print("All options cannot be false!")
        return None

    # Create a string collection to choose the characters from
    str_collection: List[str] = []

    if uppercase:
        str_collection.append(string.ascii_uppercase)
    if lowercase:
        str_collection.append(string.ascii_lowercase)
    if numbers:
        str_collection.append(string.digits)
    if specials:
        str_collection.append(string.punctuation)

    for tries in range(3):
        password = ""
        upper_num = lower_num = number_num = special_num = 0

        for i in range(length):
            char_collection = choice(str_collection)
            randomChar = choice(char_collection)

            if char_collection == string.ascii_uppercase:
                upper_num += 1

            elif char_collection == string.ascii_lowercase:
                lower_num += 1

            elif char_collection == string.digits:
                number_num += 1

            elif char_collection == string.punctuation:
                special_num += 1

            password += randomChar

        if (
            (upper_num > 0) == uppercase and
            (lower_num > 0) == lowercase and
            (number_num > 0) == numbers and
            (special_num > 0) == specials
        ):
            return password

    print("Could not generate password", file=stderr)
    print(f"Tried {tries + 1} times", file=stderr)
    return None
