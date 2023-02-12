from typing import Union

# TODO: Later return error messages for each validation

def validate_db_port(value: Union[str, None]):
    if value == None:
        return False
    # Validate the db_port
    try:
        value = int(value)
    except ValueError:
        return False
    if value < 1 or value > 65535:
        return False
    return True


def validate_db_type(value: Union[str, None]):
    if value == None:
        return False
    # Validate the db_type
    if value not in {"mysql", "mongo"}:
        return False
    return True


def validate_db_host(value: Union[str, None]):
    if value == None:
        return False
    # Validate the db_host
    if value == "":
        return False
    return True


def validate_db_user(value: Union[str, None]):
    if value == None:
        return False
    # Validate the db_user
    if value == "":
        return False
    return True


def validate_db_name(value: Union[str, None]):
    if value == None:
        return False
    # Validate the db_name
    if value == "":
        return False
    return True

def validate_file_path(file_path: str):
    # Validate the file_path
    if file_path == "":
        return False
    return True

CONFIG_KEYS = {"file_path", "db_type", "db_host", "db_user", "db_name", "db_port"}


CONFIG_KEY_VALIDATORS = {
    "file_path": validate_file_path,
    "db_type": validate_db_type,
    "db_host": validate_db_host,
    "db_user": validate_db_user,
    "db_name": validate_db_name,
    "db_port": validate_db_port,
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

        return True

    def __str__(self):
        # Return the config as a string
        return str(self.get_dict())

    def merge_config(self, config: "Configuration", overwrite: bool = False):
        # Merge the config with another config
        for key in CONFIG_KEYS:
            config_val = getattr(config, key)
            config_val_valid = CONFIG_KEY_VALIDATORS[key](config_val)

            if config_val_valid and (overwrite or getattr(self, key) is None):
                setattr(self, key, getattr(config, key))
