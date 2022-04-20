from sys import stderr
from base64 import b64decode
import pyperclip

from passwords import decrypt_string


class RawCredential:
    # TODO: Add a get_json function
    def __init__(self, id: int | str, title: str, username: str, email: str, password: str, salt: str):
        self.id = id
        self.title = b64decode(title)
        self.username = b64decode(username)
        self.email = b64decode(email)
        self.password = b64decode(password)
        self.salt = b64decode(salt)

    def __str__(self):
        string = "\n"
        string += "-------------------------------\n"
        string += "ID: {0}\n".format(self.id)
        string += "Title: {0}\n".format(self.title)
        string += "Username: {0}\n".format(self.username)
        string += "Email Address: {0}\n".format(self.email)
        string += "Encrypted Password: {0}\n".format(self.password)
        string += "Salt: {0}\n".format(self.salt)
        string += "-------------------------------"
        return string

    def get_credential(self, master_password: str):
        title = decrypt_string(master_password, self.title, self.salt)
        username = decrypt_string(master_password, self.username, self.salt)
        email = decrypt_string(master_password, self.email, self.salt)
        password = decrypt_string(master_password, self.password, self.salt)
        return Credential(self.id, title, username, email, password)

    def get_obj(self):
        return {
            "id": self.id,
            "title": self.title,
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "salt": self.salt
        }

class Credential:
    def __init__(self,  id: int | str, title: str, username: str, email: str, password: str) -> None:
        self.id = id
        self.title = title
        self.username = username
        self.email = email
        self.password = password

    def __str__(self):
        output = "\n"
        output += "-------------------------------\n"
        output += "ID: {0}\n".format(self.id)
        output += "Title: {0}\n".format(self.title)
        output += "Username: {0}\n".format(self.username)
        output += "Email Address: {0}\n".format(self.email)
        output += "Password: {0}\n".format(self.password)
        output += "-------------------------------"
        return output

    def copy_pass(self):
        try:
            pyperclip.copy(self.password)
            print("This password has been copied to your clipboard!")
        except Exception as e:
            print("This password could not be copied to your clipboard due to the following error: ", file=stderr)
            print(e, file=stderr)
