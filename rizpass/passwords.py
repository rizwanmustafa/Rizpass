import secrets
from sys import stderr
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from secrets import choice
from typing import List, Dict, Tuple, Union
import base64
import string

from .output import format_colors, print_red
from .validator import ensure_type


def get_pass_details(password: str) -> Dict[str, int]:
    ensure_type(password, str, "password", "str")

    uppercase = lowercase = digits = special = length = 0

    for char in password:
        if char in string.ascii_uppercase:
            uppercase += 1
        elif char in string.ascii_lowercase:
            lowercase += 1
        elif char in string.digits:
            digits += 1
        else:
            special += 1
        length += 1

    return {
        "length": length,
        "uppercase": uppercase,
        "lowercase": lowercase,
        "digits": digits,
        "special": special,
    }


def follows_password_requirements(
    password: str,
    min_length: int = 16,
    min_uppercase: int = 3,
    min_lowercase: int = 3,
    min_digits: int = 2,
    min_special: int = 2,
) -> Tuple[bool, List[str]]:
    ensure_type(password, str, "password", "str")
    ensure_type(min_length, int, "min_length", "int")
    ensure_type(min_uppercase, int, "min_uppercase", "int")
    ensure_type(min_lowercase, int, "min_lowercase", "int")
    ensure_type(min_digits, int, "min_digits", "int")
    ensure_type(min_special, int, "min_special", "int")

    pass_details = get_pass_details(password)
    pass_errors = []

    if pass_details["length"] < min_length:
        error = f"Length of password is {{red}}{pass_details['length']}{{reset}} but must be at least {{green}}{min_length}{{reset}}"
        pass_errors.append(format_colors(error))

    if pass_details["uppercase"] < min_uppercase:
        error = f"Number of uppercase characters is {{red}}{pass_details['uppercase']}{{reset}} but must be at least {{green}}{min_uppercase}{{reset}}"
        pass_errors.append(format_colors(error))

    if pass_details["lowercase"] < min_lowercase:
        error = f"Number of lowercase characters is {{red}}{pass_details['lowercase']}{{reset}} but must be at least {{green}}{min_lowercase}{{reset}}"
        pass_errors.append(format_colors(error))

    if pass_details["digits"] < min_digits:
        error = f"Number of digits is {{red}}{pass_details['digits']}{{reset}} but must be at least {{green}}{min_digits}{{reset}}"
        pass_errors.append(format_colors(error))

    if pass_details["special"] < min_special:
        error = f"Number of special characters is {{red}}{pass_details['special']}{{reset}} but must be at least {{green}}{min_special}{{reset}}"
        pass_errors.append(format_colors(error))

    return (len(pass_errors) == 0, pass_errors)


def __get_custom_fernet_object(master_pass: str, salt: bytes) -> Fernet:
    master_pass = bytes(master_pass, "utf-8")

    # Get custom key for Fernet using user's master password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_pass))

    return Fernet(key)


def encrypt_string(master_pass: str, raw_password: str, salt: bytes) -> Union[bytes,None]:
    try:
        ensure_type(master_pass, str, "master_pass", "str")
        ensure_type(raw_password, str, "raw_password", "str")
        ensure_type(salt, bytes,  "salt", "bytes")

        # Make sure that parameters are not empty
        if not master_pass:
            raise ValueError("Parameter 'master_pass' cannot be empty")
        if not raw_password:
            raise ValueError("Parameter 'raw_password' cannot be empty")
        if not salt:
            raise ValueError("Parameter 'salt' cannot be empty")

        fernet_object: Fernet = __get_custom_fernet_object(master_pass, salt)
        password_bytes: bytes = bytes(raw_password, "utf-8")
        encryptedPassword = fernet_object.encrypt(password_bytes)

        return encryptedPassword
    except Exception as e:
        print_red("There was an error encrypting the password:", file=stderr)
        print_red(e, file=stderr)
        return None


def decrypt_string(master_pass: str, encrypted_password: bytes, salt: bytes) -> Union[str,None]:
    try:
        ensure_type(master_pass, str, "master_pass", "str")
        ensure_type(encrypted_password, bytes, "encrypted_password", "bytes")
        ensure_type(salt, bytes, "salt", "bytes")

        # Make sure that parameters are not empty
        if not master_pass:
            raise ValueError("Parameter 'master_pass' cannot be empty")
        if not salt:
            raise ValueError("Parameter 'salt' cannot be empty")
        if not encrypted_password:
            return ''

        fernet_object: Fernet = __get_custom_fernet_object(master_pass, salt)
        password_bytes: bytes = fernet_object.decrypt(encrypted_password)
        raw_password: str = str(password_bytes, "utf-8")

        return raw_password
    except Exception as e:
        print_red("There was an error decrypting the password:", file=stderr)
        print_red(e, file=stderr)
        return None


def encrypt_and_encode(master_pass: str, data: str, salt: bytes) -> Union[str,None]:
    if not data:
        return ''

    ensure_type(master_pass, str, "master_pass", "str")
    ensure_type(data, str, "data", "str")
    ensure_type(salt, bytes, "salt", "bytes")

    return base64.b64encode(encrypt_string(master_pass, data, salt)).decode("ascii")


def decode_and_decrypt(master_pass: str, data: str, salt: bytes) -> Union[str,None]:
    if not data:
        return ''

    ensure_type(master_pass, str, "master_pass", "str")
    ensure_type(data, str, "data", "str")
    ensure_type(salt, bytes, "salt", "bytes")

    decrypted_data = decrypt_string(master_pass, base64.b64decode(data), salt)
    return decrypted_data if decrypted_data else ""


def generate_password(length: int, uppercase: bool, lowercase: bool, digits: bool, specials: bool, suppress_output: bool = False) -> Union[str,None]:
    # Exception handling
    ensure_type(length, int,  "length", "int")
    ensure_type(uppercase, bool, "uppercase", "bool")
    ensure_type(lowercase, bool, "lowercase", "bool")
    ensure_type(digits, bool, "digits", "bool")
    ensure_type(specials, bool, "specials", "bool")

    if uppercase == lowercase == digits == specials == False:
        suppress_output or print("All options cannot be false!")
        return None

    # Create a string collection to choose the characters from
    str_collection: str = ""

    if uppercase:
        str_collection += string.ascii_uppercase
    if lowercase:
        str_collection += string.ascii_lowercase
    if digits:
        str_collection += string.digits
    if specials:
        str_collection += string.punctuation

    while True:
        password = ""
        upper_num = lower_num = number_num = special_num = 0

        for _ in range(length):
            random_char = choice(str_collection)

            if random_char in string.ascii_uppercase:
                upper_num += 1

            elif random_char in string.ascii_lowercase:
                lower_num += 1

            elif random_char in string.digits:
                number_num += 1

            elif random_char in string.punctuation:
                special_num += 1

            password += random_char

        if (
            (upper_num > 0) == uppercase and
            (lower_num > 0) == lowercase and
            (number_num > 0) == digits and
            (special_num > 0) == specials
        ):
            return password


    # suppress_output or print("Could not generate password", file=stderr)
    # suppress_output or print(f"Tried {tries + 1} times", file=stderr)
    # return None


def generate_salt(length: int) -> Union[bytes,None]:
    # Exception handling
    ensure_type(length, int, "length", "int")
    return secrets.token_bytes(length)
