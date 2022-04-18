from sys import stderr
import pyperclip
from passwords import decrypt_password
from base64 import b64decode


class RawCredential:
    def __init__(self, id: int | str, title: str, username: str, email: str, password: str, salt: str):
        # Later don't decode title and other text fields, instead decode them in the Credential class
        # TODO: Use if is_pass_object_list rather than lengthy ternarys
        self.id = id
        self.title = b64decode(title).decode("utf-8")
        self.username = b64decode(username).decode("utf-8")
        self.email = b64decode(email).decode('utf-8')
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
        password = decrypt_password(
            master_password, self.password, self.salt)
        return Credential(self.id, self.title, self.username, self.email, password)


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
