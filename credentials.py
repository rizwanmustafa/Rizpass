import pyperclip
from passwords import decrypt_password


class RawCredential:
    def __init__(self, *args) -> None:
        # If we are given an array, process it. Else process the separate parameters
        pass_object = args[0] if len(args) == 1 else args

        self.id = pass_object[0]
        self.title = pass_object[1]
        self.username = pass_object[2]
        self.email = pass_object[3]
        self.encrypted_password = pass_object[4]
        self.salt = pass_object[5]

    def __str__(self):
        string = "\n"
        string += "-------------------------------\n"
        string += "ID: {0}\n".format(self.id)
        string += "Title: {0}\n".format(self.title)
        string += "Username: {0}\n".format(self.username)
        string += "Email Address: {0}\n".format(self.email)
        string += "Encrypted Password: {0}\n".format(self.encrypted_password)
        string += "Salt: {0}\n".format(self.salt)
        string += "-------------------------------"
        return string

    def get_credential(self, master_password: str):
        password = decrypt_password(
            master_password, self.encrypted_password, self.salt)
        return Credential(self.id, self.title, self.username, self.email, password)


class Credential:
    def __init__(self, *args) -> None:
        # If we are given an array, process it. Else process the separate parameters
        pass_object = args[0] if len(args) == 1 else args

        self.id = pass_object[0]
        self.title = pass_object[1]
        self.username = pass_object[2]
        self.email = pass_object[3]
        self.password = pass_object[4]

    def __str__(self):
        string = "\n"
        string += "-------------------------------\n"
        string += "ID: {0}\n".format(self.id)
        string += "Title: {0}\n".format(self.title)
        string += "Username: {0}\n".format(self.username)
        string += "Email Address: {0}\n".format(self.email)
        string += "Password: {0}\n".format(self.password)
        string += "-------------------------------"
        return string

    def copy_pass(self):
        try:
            pyperclip.copy(self.password)
            print("This password has been copied to your clipboard!")
        except Exception as e:
            print("This password could not be copied to your clipboard due to the following error: ")
            print(e)
