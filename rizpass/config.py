from typing import Union

CONFIG_KEYS = {"file_path", "db_type", "db_host", "db_user", "db_name", "db_port"}

def validate_db_port(db_port: str):
    # Validate the db_port
    try:
        db_port = int(db_port)
    except ValueError:
        return False
    if db_port < 1 or db_port > 65535:
        return False
    return True

def validate_db_type(db_type: str):
    # Validate the db_type
    if db_type not in {"mysql", "mongo"}:
        return False
    return True

def validate_db_host(db_host: str):
    # Validate the db_host
    if db_host == "":
        return False
    return True

def validate_db_user(db_user: str):
    # Validate the db_user
    if db_user == "":
        return False
    return True

def validate_db_name(db_name: str):
    # Validate the db_name
    if db_name == "":
        return False
    return True

def validate_file_path(file_path: str):
    # Validate the file_path
    if file_path == "":
        return False
    return True


CONFIG_KEY_VALIDATORS = {
    "file_path": lambda x: isinstance(x, str),
    "db_type": lambda x: isinstance(x, str),
    "db_host": lambda x: isinstance(x, str),
    "db_user": lambda x: isinstance(x, str),
    "db_name": lambda x: isinstance(x, str),
    "db_port": lambda x: isinstance(x, str),
}


class Configuration:
    # All the configuration variables are set to None by default
    # All the configuration variables are of type string
    def __init__(
        self,
        file_path: Union[str, None] = None,
        db_type: Union[str, None] = None,
        db_host: Union[str, None] = None,
        db_user: Union[str, None] = None,
        db_name: Union[str, None] = None,
        db_port: Union[str, None] = None
    ):
        self.file_path = file_path
        self.db_type = db_type
        self.db_host = db_host
        self.db_user = db_user
        self.db_name = db_name
        self.db_port = db_port

    def parse_from_dict(self, config_dict: dict):
        # Parse the config from a dictionary
        for key in config_dict:
            if key in CONFIG_KEYS:
                setattr(self, key, config_dict[key])

    def get_dict(self):
        # Return the config as a dictionary
        config_dict = dict()
        for key in CONFIG_KEYS:
            config_dict[key] = getattr(self, key)
        return config_dict

    def validate_config(self):
        # Validate the config
        for key in CONFIG_KEYS:
            if getattr(self, key) is None:
                return False
            if not CONFIG_KEY_VALIDATORS[key](getattr(self, key)):
                return False
        if not validate_db_port(self.db_port):
            return False
        if not validate_db_type(self.db_type):
            return False
        if not validate_db_host(self.db_host):
            return False
        if not validate_db_user(self.db_user):
            return False
        if not validate_db_name(self.db_name):
            return False
        return True

    def __str__(self):
        # Return the config as a string
        return str(self.get_dict())