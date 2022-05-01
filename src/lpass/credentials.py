from sys import stderr
from base64 import b64decode
import pyperclip
from colorama import Fore, Style

from .passwords import decode_and_decrypt
from .validator import ensure_type


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
        output += f"{Style.BRIGHT}-------------------------------{Style.RESET_ALL}\n"
        output += f"{Style.BRIGHT}ID:{Style.RESET_ALL} {self.id}\n"
        output += f"{Style.BRIGHT}Title:{Style.RESET_ALL} {self.title}\n"
        output += f"{Style.BRIGHT}Username:{Style.RESET_ALL} {self.username}\n"
        output += f"{Style.BRIGHT}Email Address:{Style.RESET_ALL} {self.email}\n"
        output += f"{Style.BRIGHT}Encrypted Password:{Style.RESET_ALL} {self.password}\n"
        output += f"{Style.BRIGHT}Salt:{Style.RESET_ALL} {self.salt}\n"
        output += f"{Style.BRIGHT}-------------------------------{Style.RESET_ALL}"
        return output

    def get_credential(self, master_password: str):
        print(f"Decrypting password with id {self.id}...")
        salt = b64decode(self.salt)
        title = decode_and_decrypt(
            master_password,
            self.title,
            salt
        )
        username = decode_and_decrypt(
            master_password,
            self.username,
            salt
        )
        email = decode_and_decrypt(
            master_password,
            self.email,
            salt
        )
        password = decode_and_decrypt(
            master_password,
            self.password,
            salt
        )
        if title != None and username != None and email != None and password != None:
            print(f"{Fore.GREEN}Decryption sucessful!{Fore.RESET}")
        else:
            print(f"{Fore.RED}Decryption failed!{Fore.RESET}")

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
        # TODO: Have a separate try catch block for this
        decrypted_password = decode_and_decrypt(
            master_pass,
            self.password,
            b64decode(self.salt)
        )
        try:
            pyperclip.copy(decrypted_password)
        except Exception as e:
            print(f"{Fore.RED}This password could not be copied to your clipboard due to the following error: {Fore.RESET}", file=stderr)
            print(f"{Fore.RED}{e}{Fore.RESET}", file=stderr)
        else:
            print(f"{Fore.GREEN}This password has been copied to your clipboard!{Fore.RESET}")


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
        string += f"{Style.BRIGHT}-------------------------------{Style.RESET_ALL}\n"
        string += f"{Style.BRIGHT}ID:{Style.RESET_ALL} {self.id}\n"
        string += f"{Style.BRIGHT}Title:{Style.RESET_ALL} {self.title}\n"
        string += f"{Style.BRIGHT}Username:{Style.RESET_ALL} {self.username}\n"
        string += f"{Style.BRIGHT}Email Address:{Style.RESET_ALL} {self.email}\n"
        string += f"{Style.BRIGHT}Password:{Style.RESET_ALL} {self.password}\n"
        string += f"{Style.BRIGHT}-------------------------------{Style.RESET_ALL}"
        return string

    def copy_pass(self):
        try:
            pyperclip.copy(self.password)
        except Exception as e:
            print(f"{Fore.RED}This password could not be copied to your clipboard due to the following error: {Fore.RESET}", file=stderr)
            print(f"{Fore.RED}{e}{Fore.RESET}", file=stderr)
        else:
            print(f"{Fore.GREEN}This password has been copied to your clipboard!{Fore.RESET}")
