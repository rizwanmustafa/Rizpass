from sys import stderr
from base64 import b64decode, b64encode
from typing import Tuple
from cryptography.fernet import InvalidToken
import pyperclip

from .validator import ensure_type
from .output import print_colored, print_red, print_green, format_colors, print_verbose


def get_raw(field_name: str, master_password: str,  encrypted_value: str, salt: bytes) -> Tuple[bool, str]:
    from .passwords import decode_and_decrypt
    try:
        ret_val = decode_and_decrypt(
            master_password,
            encrypted_value,
            salt
        )
    except InvalidToken:
        ret_val = format_colors(f"{{red}}DECRYPTION ERROR{{reset}}")
        print_red(f"Error while decrypting the {field_name}!", file=stderr)
        print_red(f"This is probably because the {field_name} is not encrypted with the master password.", file=stderr)
        print_colored(f"{{red}}Encrypted and encoded {field_name}:{{reset}} {encrypted_value}", file=stderr)
        print()
    except Exception as e:
        ret_val = f"Error while decrypting the {field_name}"
        print_red(f"Error while decrypting the {field_name}:", file=stderr)
        print_red(e, file=stderr)
        print_colored(f"{{red}}Encrypted and encoded {field_name}:{{reset}} {encrypted_value}", file=stderr)
        print()
    else:
        print_verbose(format_colors(f"{{green}}Successfully decrypted {field_name}!{{reset}}"))
        return True, ret_val
    finally:
        return False, ret_val


class RawCredential:
    """This takes in encrypted and base64 encoded credentials and returns a RawCredential object."""
    # TODO: Add a get_json function

    def __init__(self, id: int, title: str, username: str, email: str, password: str, salt: str):
        ensure_type(id, int, "id", "int")
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, str, "password", "string")

        self.id = id
        self.title = title
        self.username = username
        self.email = email
        self.password = password
        self.salt = salt

    def __str__(self):
        output = "\n"
        output += f"{{blue}}-------------------------------{{reset}}\n"
        output += f"{{blue}}ID:{{reset}} {self.id}\n"
        output += f"{{blue}}Title:{{reset}} {self.title}\n"
        output += f"{{blue}}Username:{{reset}} {self.username}\n"
        output += f"{{blue}}Email:{{reset}} {self.email}\n"
        output += f"{{blue}}Password:{{reset}} {self.password}\n"
        output += f"{{blue}}Salt:{{reset}} {self.salt}\n"
        output += f"{{blue}}-------------------------------{{reset}}"
        return format_colors(output)

    def get_credential(self, master_password: str):
        from .passwords import decode_and_decrypt
        print_verbose(f"Decrypting credential with id {self.id}...")
        salt = b64decode(self.salt)

        title = get_raw("title", master_password, self.title, salt)[1]
        username = get_raw("username", master_password, self.username, salt)[1]
        email = get_raw("email", master_password, self.email, salt)[1]
        password = get_raw("password", master_password, self.password, salt)[1]

        if title != None and username != None and email != None and password != None:
            print_verbose("{green}Credential decryption successful!{reset}")
        else:
            print_verbose("{red}Credential decryption failed!{reset}", file=stderr)

        return Credential(self.id, title, username, email, password)

    def get_obj(self):
        return {
            "id": self.id,
            "title": self.title,
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "salt": self.salt,
        }

    def copy_pass(self, master_pass: str):
        decrypted_password = get_raw("password", master_pass, self.password, b64decode(self.salt))

        if not decrypted_password[0]:
            return

        try:
            pyperclip.copy(decrypted_password)
        except Exception as e:
            print_red("This password could not be copied to your clipboard due to the following error:", file=stderr)
            print_red(e, file=stderr)
        else:
            print_green(f"This password has been copied to your clipboard!")


class Credential:
    def __init__(self,  id: int, title: str, username: str, email: str, password: str) -> None:
        ensure_type(id, int, "id", "int")
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, str, "password", "string")

        self.id = id
        self.title = title
        self.username = username
        self.email = email
        self.password = password

    def __str__(self):
        string = "\n"
        string += f"{{blue}}-------------------------------{{reset}}\n"
        string += f"{{blue}}ID:{{reset}} {self.id}\n"
        string += f"{{blue}}Title:{{reset}} {self.title}\n"
        string += f"{{blue}}Username:{{reset}} {self.username}\n"
        string += f"{{blue}}Email:{{reset}} {self.email}\n"
        string += f"{{blue}}Password:{{reset}} {self.password}\n"
        string += f"{{blue}}-------------------------------{{reset}}"
        return format_colors(string)

    def get_raw_credential(self, master_pass: str, salt: bytes) -> RawCredential:
        ensure_type(master_pass, str, "master_pass", "string")
        ensure_type(salt, bytes, "salt", "bytes")
        from .passwords import encrypt_and_encode

        title = encrypt_and_encode(
            master_pass,
            self.title,
            salt
        )
        username = encrypt_and_encode(

            master_pass,
            self.username,
            salt
        )
        email = encrypt_and_encode(
            master_pass,
            self.email,
            salt


        )
        password = encrypt_and_encode(
            master_pass,
            self.password,
            salt
        )
        if title != None and username != None and email != None and password != None:
            print_verbose("{green}Encryption sucessful!{reset}")

        return RawCredential(
            self.id,
            title,
            username,
            email,
            password,
            b64encode(salt).decode()
        )

    def copy_pass(self, suppress_output: bool = False) -> None:
        try:
            pyperclip.copy(self.password)
        except NotImplementedError:
            suppress_output or print_red("Pyperclip is not available on your system. Please install it to use this feature.")
        except Exception as e:
            suppress_output or print_red("This password could not be copied to your clipboard due to the following error:", file=stderr)
            suppress_output or print_red(e, file=stderr)
        else:
            suppress_output or print_green("This password has been copied to your clipboard!")
