from typing import List, Union

from .credentials import RawCredential
from .validator import ensure_type

from .credentials import RawCredential

class DbConfig:
    def __init__(self, host: str, user: str, password: str, db: str, port: Union[int, None] = None):
        ensure_type(host, str, "host", "string")
        ensure_type(user, str, "user", "string")
        ensure_type(password, str, "password", "string")
        ensure_type(db, str, "db", "string")
        ensure_type(port, Union[int, None], "port", "int | None")

        self.host = host
        self.user = user
        self.password = password
        self.db = db
        self.port = port

class DbManager:

    def __init__(self):
        pass

    def add_credential(self, title: str, username: str, email: str, password: str, salt: str) -> int:
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

    def close(self):
        pass

    def get_mode(self) -> str:
        pass

    def __del__(self):
        pass
