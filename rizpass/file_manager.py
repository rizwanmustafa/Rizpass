from os import path
from sys import stderr
from json import load as load_json, dump as dump_json
from typing import List, Union

from .credentials import RawCredential
from .validator import ensure_type
from .output import format_colors, print_red, print_verbose
from .cred_manager import CredManager

# TODO: Convert credentials from an array to an object with id as key


class FileManager(CredManager):
    credentials: List[RawCredential]

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.load_creds()

    def __del__(self):
        self.close()

    def open_file(self):
        """
        Opens the credential file for reading and writing and assigns it to self.file.
        """
        print_verbose(f"Opening file located at: '{self.file_path}'", file=stderr)
        if not hasattr(self, "file_path"):
            print_red("No file path specified", file=stderr)
            exit(1)

        try:
            if path.isfile(self.file_path):
                self.file = open(self.file_path, "r+")
                self.file.write("[]") if self.file.readlines() == [] else None
            else:
                self.file = open(self.file_path, "w+")
                self.file.write("[]")

            self.file.seek(0, 0)
        except PermissionError:
            print_red(f"Permission denied to create/modify file: \'{self.file_path}\'", file=stderr)
            exit(1)

        except Exception as e:
            print_red(f"There was an error while creating/modifying the file \"{self.file_path}\":", file=stderr)
            print_red(e, file=stderr)
            exit(1)
        else:
            print_verbose(format_colors("{green}File opened successfully{reset}"))

    def load_creds(self):
        """
        Opens the file and loads the credentials from it.
        """
        self.open_file()
        print_verbose("Loading credentials from file")
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
        self.close_file()
        print_verbose(format_colors("{green}Credentials loaded successfully{reset}"))

    def dump_creds(self):
        """
        Dumps the credentials in the memory to the file.
        """
        self.open_file()
        print_verbose("Dumping credentials to file")
        self.file.truncate(0)
        export_creds = []

        for cred in self.credentials:
            export_creds.append(cred.get_obj())

        dump_json(export_creds, self.file)
        self.close_file()
        print_verbose(format_colors("{green}Credentials dumped successfully{reset}"))

    def __gen_id(self) -> int:
        """
        Generates a unique id for a new credential.
        """
        id = len(self.credentials) + 1
        while self.get_credential(id):
            id += 1
        return id

    def close_file(self):
        """
        Closes the credential file if opened
        """
        if hasattr(self, "file"):
            self.file.close()
            del self.file

    def close(self):
        self.close_file()

    def add_credential(self, title: str, username: str, email: str, password: str, salt: str) -> int:
        """This method takes in the encrypted and encoded credentials and adds them to the file."""
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, str, "password", "string")
        ensure_type(salt, str, "salt", "string")

        id = self.__gen_id()

        self.credentials.append(RawCredential(
            id,
            title,
            username,
            email,
            password,
            salt
        ))

        self.dump_creds()

        return id

    def get_all_credentials(self) -> Union[List[RawCredential], None]:
        """
        Returns the credentials stored in memory.
        """
        return self.credentials

    def get_credential(self, id: int) -> Union[RawCredential, None]:
        """
        Returns a credential with the given id if it exists. Otherwise, returns None.
        """
        query_result = None
        for i in self.credentials:
            if i.id == id:
                query_result = i
                break

        return query_result

    def remove_credential(self, id: int) -> None:
        """
        Removes a credential with the given id if it exists.
        """

        for index, cred in enumerate(self.credentials):
            if cred.id == id:
                self.credentials.pop(index)
                break
        else:
            print_red(f"Credential with id {id} not found", file=stderr)

        self.dump_creds()

    def remove_all_credentials(self) -> None:
        """
        Removes all credentials that may be present in the file.
        """
        self.credentials = []
        self.dump_creds()

    def modify_credential(self, id: int, title: str, username: str, email: str, password: str, salt: str) -> None:
        """
        Modifies a credential with the given id if it exists.
        """
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

        self.dump_creds()

    def get_mode(self) -> str:
        """
        Returns the mode of credential storage.
        """
        return "file"
