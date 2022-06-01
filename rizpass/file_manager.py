from os import path
from sys import stderr
from json import load as load_json, dump as dump_json
from typing import List, Union

from .credentials import RawCredential, Credential
from .validator import ensure_type
from .output import print_red

# TODO: Convert credentials from an array to an object with id as key


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
            print_red(f"There was an error while opening the file \"{file_path}\":", file=stderr)
            print_red(e, file=stderr)
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

    def add_credential(self, title: str, username: str, email: str, password: str, salt: str) -> None:
        """This method takes in the encrypted and encoded credentials and adds them to the file."""
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, str, "password", "string")
        ensure_type(salt, str, "salt", "string")

        id = self.__gen_id()

        try:
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
            print_red("There was an error while adding the credential:", file=stderr)
            print_red(e, file=stderr)

    def get_all_credentials(self) -> Union[List[RawCredential],None]:
        return self.credentials

    def get_credential(self, id: int) -> Union[RawCredential,None]:
        query_result = None
        for i in self.credentials:
            if i.id == id:
                query_result = i
                break

        return query_result

    def remove_credential(self, id: int) -> None:

        for index, cred in enumerate(self.credentials):
            if cred.id == id:
                self.credentials.pop(index)
                break
        else:
            print_red(f"Credential with id {id} not found", file=stderr)

        self.__dump_creds()

    def remove_all_credentials(self) -> None:
        self.credentials = []
        self.__dump_creds()

    def modify_credential(self, id: int, title: str, username: str, email: str, password: str, salt: str) -> None:
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, str, "password", "string")
        ensure_type(salt, str, "salt", "string")

        for index, cred in enumerate(self.credentials):
            if cred.id == id:
                self.credentials[index] = RawCredential(
                    id,
                    title,
                    username,
                    email,
                    password,
                    salt
                )
                break

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

    def get_mode(self) -> str:
        return "file"
