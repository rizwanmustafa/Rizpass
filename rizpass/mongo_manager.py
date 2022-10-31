from sys import exit, stderr
from typing import List
from typing import List, Union
from urllib.parse import quote_plus


from .credentials import RawCredential
from .validator import ensure_type
from .output import print_red
from .db_manager import DbManager, DbConfig

class MongoManager(DbManager):

    def __init__(self,  db_config: DbConfig):
        ensure_type(db_config, DbConfig, "db_config", "DbConfig")
        from pymongo.mongo_client import MongoClient
        from pymongo import ASCENDING

        try:
            self.mongo_client = MongoClient(
                host=quote_plus(db_config.host),
                username=quote_plus(db_config.user) if db_config.user and db_config.password else None,
                password=quote_plus(db_config.password) if db_config.user and db_config.password else None,
                port=db_config.port if db_config.port else None,
                authSource=db_config.db,
                serverSelectionTimeoutMS=3000,
                connectTimeoutMS=3000,
                socketTimeoutMS=3000
            )
            self.mongo_client.server_info()  # To make sure that the mongo instance is valid
            self.mongo_db = self.mongo_client[db_config.db]
            self.mongo_collection = self.mongo_db["credentials"]

            self.mongo_collection.create_index([("id", ASCENDING)], unique=True)
        except Exception as e:
            print()
            print_red("There was an error while connecting with MongoDB:", file=stderr)
            print_red(e, file=stderr)
            print_red()
            print_red("Exiting with code 1!", file=stderr)
            exit(1)

    def __gen_id(self) -> Union[int, None]:
        """This method will generate a unique id for the credential. Note: To be used only with MongoDB"""
        id = self.mongo_collection.estimated_document_count() + 1
        while self.get_credential(id):
            id += 1
        return id

    def add_credential(self, title: str, username: str, email: str, password: str, salt: str) -> int:
        """This method takes in the encrypted and encoded credentials and adds them to the database."""
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, str, "password", "string")
        ensure_type(salt, str, "salt", "string")

        # Encode to b64
        cred_id = self.__gen_id()

        # Add the password to the database
        self.mongo_collection.insert_one({
            "id": cred_id,
            "title": title,
            "username": username,
            "email": email,
            "password": password,
            "salt": salt
        })

        return cred_id

    def get_all_credentials(self) -> List[RawCredential]:
        raw_creds: List[RawCredential] = []

        for i in self.mongo_collection.find():
            raw_creds.append(RawCredential(i["id"], i["title"], i["username"], i["email"], i["password"], i["salt"]))

        return raw_creds

    def get_credential(self, id: int) -> Union[RawCredential, None]:
        ensure_type(id, int, "id", "int")

        query_result = self.mongo_collection.find_one({"id": id})
        if not query_result:
            return None

        return RawCredential(
            query_result["id"],
            query_result["title"],
            query_result["username"],
            query_result["email"],
            query_result["password"],
            query_result["salt"]
        )

    def remove_credential(self, id: int) -> None:
        ensure_type(id, int, "id", "int")

        self.mongo_collection.delete_one({"id": id})

    def remove_all_credentials(self) -> None:
        self.mongo_collection.delete_many({})

    def modify_credential(self, id: int, title: str, username: str, email: str, password: str, salt: str) -> None:
        ensure_type(id, int, "id", "int")
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, str, "password", "string")
        ensure_type(salt, str, "salt", "string")

        self.mongo_collection.update_one({"id": id}, {"$set": {
            "title": title,
            "username": username,
            "email": email,
            "password": password,
            "salt": salt
        }})

    def close(self):
        try:
            if hasattr(self, "mongo_client"):
                self.mongo_client.close()
        except Exception as e:
            print_red("There was an error while closing connection with MongoDB:", file=stderr)
            print_red(e, file=stderr)

    def get_mode(self) -> str:
        return "mongo"

    def __del__(self):
        self.close()
