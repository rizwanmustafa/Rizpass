from os import path
from sys import stderr
from base64 import b64encode, b64decode
from json import load as load_json, dump as dump_json
from typing import List
from getpass import getpass

from credentials import RawCredential, Credential
from validator import ensure_type
from passwords import decrypt_string, encrypt_string

# TODO: Convert credentials from an array to an object with id as key
# TODO: Rather than appending raw objects into the self.credentials, append RawCredentials instead.
# Then upon dumping, use the get_object function to get the object.


class FileManager:
    credentials: List[RawCredential]

    def __init__(self, file_path: str):
        try:
            if path.isfile(file_path):
                self.file = open(file_path, "r+")
                self.file.write("[]") if self.file.readlines() == [] else None
            else:
                self.file = open(file_path, "w+")
                self.file.write("[]")

            self.__load_creds()

        except Exception as e:
            print(f"There was an error while opening the file \"{file_path}\":", file=stderr)
            print(e, file=stderr)
            exit(1)

    def __del__(self):
        self.close()

    def __load_creds(self):
        self.credentials: List[RawCredential] = []
        self.file.seek(0, 0)
        import_creds = load_json(self.file)
        for import_cred in import_creds:
            self.credentials.append(RawCredential(
                import_cred["id"],
                import_cred["title"],
                import_cred["username"],
                import_cred["email"],
                import_cred["password"],
                import_cred["salt"]
            ))
        self.credentials.sort(key=lambda x: x.id)
        self.file.seek(0, 0)

    def __dump_creds(self):
        self.file.seek(0, 0)
        self.file.truncate(0)
        export_creds = []

        for cred in self.credentials:
            export_creds.append(cred.get_obj())

        dump_json(export_creds, self.file)
        self.file.seek(0, 0)

    def __gen_id(self) -> int:
        id = len(self.credentials) + 1
        while self.get_credential(id):
            id += 1
        return id

    def close(self):
        self.file.close()

    def add_credential(self, title: bytes, username: bytes, email: bytes, password: bytes, salt: bytes) -> None:
        """This method takes in the encrypted credentials and adds them to the file."""
        id = self.__gen_id()
        title = b64encode(title).decode("ascii")
        username = b64encode(username).decode("ascii")
        email = b64encode(email).decode("ascii")
        password = b64encode(password).decode("ascii")
        salt = b64encode(salt).decode("ascii")

        # Add the password to the database
        try:
            # TODO: Replace with RawCredential.get_json()

            self.credentials.append(RawCredential(
                id,
                title,
                username,
                email,
                password,
                salt
            ))

            self.__dump_creds()
        except Exception as e:
            print("There was an error while adding the credential:", file=stderr)
            print(e, file=stderr)

    def get_all_credentials(self) -> List[RawCredential] | None:
            return self.credentials

    def get_credential(self, id: int | str) -> RawCredential | None:
        query_result = None
        for i in self.credentials:
            if i.id == id:
                query_result = i
                break

        return query_result

    def remove_credential(self, id: int | str) -> None:
        cred_index = None

        for index, cred in enumerate(self.credentials):
            if cred.id == id:
                cred_index = index

        if not cred_index:
            print("No credential with the given id exists!", file=stderr)
            return

        self.credentials.pop(cred_index)
        self.__dump_creds()

    def remove_all_credentials(self) -> None:
        self.credentials = []
        self.__dump_creds()

    def modify_credential(self, id: int, title: str, username: str, email: str, password: bytes, salt: bytes) -> None:

        originalPassword = self.get_credential(id)
        if not originalPassword:
            print("No credential with the given id exists!", file=stderr)
            return

        title = title if title else originalPassword.title
        title = b64encode(title).decode("ascii")

        username = username if username else originalPassword.username
        username = b64encode(username).decode("ascii")

        email = email if email else originalPassword.email
        email = b64encode(email).decode("ascii")

        password = password if password else originalPassword.password
        password = b64encode(password).decode("ascii")

        salt = salt if salt else originalPassword.salt
        salt = b64encode(salt).decode("ascii")

        for index, cred in enumerate(self.credentials):
            if cred.id == id:
                self.credentials[index].id = id
                self.credentials[index].title = title
                self.credentials[index].username = username
                self.credentials[index].email = email
                self.credentials[index].password = password
                self.credentials[index].salt = salt

        self.__dump_creds()

    def filter_credentials(self, title: str, username: str, email: str, master_pass: str) -> List[Credential]:
        raw_creds: List[RawCredential] = self.get_all_credentials()
        if raw_creds == []:
            return raw_creds

        filtered_creds: List[Credential] = []
        for raw_cred in raw_creds:
            cred = raw_cred.get_credential(master_pass)
            title_match = title.lower() in cred.title.lower()
            username_match = username.lower() in cred.username.lower()
            email_match = email.lower() in cred.email.lower()

            if title_match and username_match and email_match:
                filtered_creds.append(cred)

        return filtered_creds

    def import_from_file(self, master_pass: str, filename: str) -> None:
        ensure_type(master_pass, str, "master_password", "string")
        ensure_type(filename, str, "filename", "string")

        if not filename:
            raise ValueError("Invalid value provided for parameter 'filename'")

        if not path.isfile(filename):
            print(f"{filename} does not exist!")
            raise Exception

        file_master_pass: str = getpass("Input master password for file: ")
        file_creds = load_json(open(filename, "r"))

        if not file_creds:
            print("There are no credentials in the file.")

        # TODO: Combine these two loops into one

        for file_cred in file_creds:
            temp_cred = {
                "title": b64decode(file_cred["title"]),
                "username": b64decode(file_cred["username"]),
                "email": b64decode(file_cred["email"]),
                "password": b64decode(file_cred["password"]),
                "salt": b64decode(file_cred["salt"]),
            }

            for i in temp_cred:
                if i == "salt":
                    continue
                decrypted_prop: str = decrypt_string(file_master_pass, temp_cred[i], temp_cred["salt"])
                temp_cred[i] = encrypt_string(master_pass, decrypted_prop, temp_cred["salt"])

            self.add_credential(
                temp_cred["title"],
                temp_cred["username"],
                temp_cred["email"],
                temp_cred["password"],
                temp_cred["salt"]
            )

        print("All credentials have been successfully added!")

# TODO: Write proper unit tests
# if __name__ == "__main__":
#     master_pass = input("Enter the master password: ")
#     # Unit tests
#     x = FileManager("passwords.json")
#     for i in x.get_all_credentials():
#         print(i.get_credential(master_pass))

#     print(x.get_password(5).get_credential(master_pass))

#     for i in x.filter_passwords("", "rizwanmustafa", ""):
#         print(i.get_credential(master_pass))

#     x.remove_password(78)

#     x.remove_all_passwords()
