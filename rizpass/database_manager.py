from sys import exit, stderr
from typing import List
from typing import List, Union
from urllib.parse import quote_plus


from .credentials import RawCredential, Credential
from .validator import ensure_type
from .output import format_colors, print_red, print_verbose
from .cred_manager import CredManager


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


class MysqlManager(CredManager):

    def __init__(self,  db_config: DbConfig):
        from .output import print_verbose, format_colors
        ensure_type(db_config, DbConfig, "db_config", "DbConfig")

        import pymysql

        print_verbose("Begin connecting to mysql!")
        try:
            self.mysql_db = pymysql.connect(
                host=db_config.host,
                user=db_config.user,
                password=db_config.password,
                db=db_config.db,
                port=db_config.port if db_config.port else 3306,
                # connection_timeout=3
            )
            self.mysql_cursor = self.mysql_db.cursor()
        except Exception as e:
            print()
            print_red("There was an error while connecting with MySQL:", file=stderr)
            print_red(e, file=stderr)
            print()
            print_red("Exiting with code 1!", file=stderr)
            exit(1)
        else:
            print_verbose(format_colors("{green}Connection established successfully!{reset}"))

    def add_credential(self, title: str, username: str, email: str, password: str, salt: str) -> int:
        from .output import print_verbose, format_colors
        """This method takes in the encrypted and encoded credentials and adds them to the database."""
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, str, "password", "string")
        ensure_type(salt, str, "salt", "string")

        # Add the credential to the database
        query = "INSERT INTO credentials(title, username, email, password, salt) VALUES('%s', '%s', '%s', '%s', '%s');" % (
            title, username, email, password, salt)
        print_verbose("Begin execution of query: ")
        print_verbose(query)

        self.mysql_cursor.execute(query)
        self.mysql_db.commit()

        print_verbose(format_colors("{green}Query executed successfully!{reset}"))

        return self.mysql_cursor.lastrowid

    def get_all_credentials(self) -> List[RawCredential]:
        raw_creds: List[RawCredential] = []

        query = "SELECT * FROM credentials WHERE title LIKE '%' AND username LIKE '%' AND email LIKE '%'"
        print_verbose("Begin execution of query: ")
        print_verbose(query)

        self.mysql_cursor.execute(query)

        print_verbose(format_colors("{green}Query executed successfully!{reset}"))

        for i in self.mysql_cursor.fetchall():
            raw_creds.append(RawCredential(i[0], i[1], i[2], i[3], i[4], i[5]))

        return raw_creds

    def get_credential(self, id: int) -> Union[RawCredential, None]:
        ensure_type(id, int, "id", "int")

        query = "SELECT * FROM credentials WHERE id = %s" % (id, )
        print_verbose("Begin execution of query: ")
        print_verbose(query)

        self.mysql_cursor.execute(query)
        print_verbose(format_colors("{green}Query executed successfully!{reset}"))

        query_result = self.mysql_cursor.fetchone()
        if not query_result:
            return None

        return RawCredential(
            query_result[0],
            query_result[1],
            query_result[2],
            query_result[3],
            query_result[4],
            query_result[5]
        )

    def remove_credential(self, id: int) -> None:
        ensure_type(id, int, "id", "int")
        if not id:
            raise ValueError("Invalid value provided for parameter 'id'")

        query = "DELETE FROM credentials WHERE id=%s" % (id, )
        print_verbose("Begin execution of query: ")
        print_verbose(query)

        self.mysql_cursor.execute(query)
        self.mysql_db.commit()
        print_verbose(format_colors("{green}Query executed successfully!{reset}"))

    def remove_all_credentials(self) -> None:
        query = "DELETE FROM credentials"
        print_verbose("Begin execution of query: ")
        print_verbose(query)

        self.mysql_cursor.execute(query)
        self.mysql_db.commit()

        print_verbose(format_colors("{green}Query executed successfully!{reset}"))

    def modify_credential(self, id: int, title: str, username: str, email: str, password: str, salt: str) -> None:
        ensure_type(id, int, "id", "int")
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, str, "password", "string")
        ensure_type(salt, str, "salt", "string")

        query = "UPDATE credentials SET title = '%s', username = '%s', email = '%s', password = '%s', salt = '%s' WHERE id = %s" % (
            title, username, email, password, salt, id)
        print_verbose("Begin execution of query: ")
        print_verbose(query)

        self.mysql_cursor.execute(query)
        self.mysql_db.commit()

        print_verbose(format_colors("{green}Query executed successfully!{reset}"))

    def close(self):
        try:
            if hasattr(self, "mysql_cursor"):
                self.mysql_cursor.close()
        except Exception as e:
            print_red("There was an error while closing the connection:", file=stderr)
            print_red(e, file=stderr)

    def get_mode(self) -> str:
        return "mysql"

    def __del__(self):
        self.close()


class MongoManager(CredManager):

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
