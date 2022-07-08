from typing import List, Union

from .credentials import RawCredential, Credential


class CredManager:

    def __init__(self):
        pass

    def add_credential(self, title: str, username: str, email: str, password: str, salt: str) -> None:
        pass

    def get_all_credentials(self) -> Union[List[RawCredential], None]:
        pass

    def get_credential(self, id: int) -> Union[RawCredential, None]:
        pass

    def remove_credential(self, id: int) -> None:
        pass

    def remove_all_credentials(self) -> None:
        pass

    def modify_credential(self, id: int, title: str, username: str, email: str, password: str, salt: str) -> None:
        pass

    def filter_credentials(self, title: str, username: str, email: str, master_pass: str) -> List[Credential]:
        pass

    def execute_raw_query(self, query: str) -> None:
        pass

    def close(self):
        pass

    def get_mode(self) -> str:
        pass

    def __del__(self):
        pass
