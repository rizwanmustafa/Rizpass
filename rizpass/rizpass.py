#!/usr/bin/env python3
from base64 import b64encode
import os
import pyperclip
import json
from getpass import getpass
from sys import exit, argv, stderr, stdout
from typing import Callable, List, Dict, NoReturn, Tuple
from cerberus import Validator as SchemaValidator
from pymongo.mongo_client import MongoClient
from colorama import init as color_init, Fore
import signal

from .misc import print_license, VERSION_NUMBER
from .output import print_green, print_red, set_colored_output, get_colored_output, print_yellow, print_magenta
from .validator import ensure_type
from .better_input import confirm, better_input, pos_int_input
from .schemas import get_config_schema
from .passwords import generate_password as generate_random_password, encrypt_and_encode, generate_salt
from .credentials import RawCredential, Credential
from .database_manager import DbConfig, MysqlManager, MongoManager
from .setup_rizpass import setup_password_manager
from .file_manager import FileManager

CONFIG_FILE_PATH = os.path.expanduser("~/.rizpass.json")

master_pass:  str = None
creds_file_path: str = None
creds_manager:  MysqlManager | MongoManager | FileManager = None

config: Dict[str, str] = {
    "file_path": None,
    "db_type": None,
    "db_host": None,
    "db_user": None,
    "db_name": None,
    "db_port": None
}


# TODO: Add requirements for master password

color_init()


def get_mode() -> str:
    if isinstance(creds_manager, FileManager):
        return "file"
    elif isinstance(creds_manager, MysqlManager):
        return "mysql"
    elif isinstance(creds_manager, MongoManager):
        return "mongo"


def perform_tasks() -> None:
    max_limit = 13

    user_choice = better_input(
        "Choice: ",
        validator=lambda x:  True if x.isnumeric() and int(x) <= max_limit and int(x) > 0 else "Choice must be <= 13 and >= 1"
    )

    if user_choice == None:
        return

    user_choice = int(user_choice)

    # print()
    clear_console()

    menu_items[user_choice][1]()

    print()
    input("Press enter to continue...")


def load_db_config(
    db_host: str | None = None,
    db_type: str | None = None,
    db_user: str | None = None,
    db_name: str | None = None,
    db_port: int | None = None
) -> bool:
    ensure_type(db_host, str | None, "db_host", "string | None")
    ensure_type(db_type, str | None, "db_type", "string | None")
    ensure_type(db_user, str | None, "db_user", "string | None")
    ensure_type(db_name, str | None, "db_name", "string | None")
    ensure_type(db_port, int | None, "db_port", "int | None")

    global config

    if not os.path.isfile(CONFIG_FILE_PATH):
        print_red("It looks like you haven't set Rizpass up.", file=stderr)
        print_red("You can do so by using the --setup flag", file=stderr)
        print_red("If you want to use Rizpass in file mode, you can use the --file flag", file=stderr)
        return False

    try:
        config_file = open(CONFIG_FILE_PATH, "r+")
        file_content = config_file.readlines()
    except Exception as e:
        print_red("Could not load configuration file due to the following error:", file=stderr)
        print_red(e, file=stderr)
        return False

    if not file_content or len(file_content) == 0:
        print_red("Configuration file is empty!", file=stderr)
        print(f"Please fix the configuration file located at {CONFIG_FILE_PATH}", file=stderr)
        return False

    config_file.seek(0, 0)
    try:
        user_settings: Dict[str, str] = json.load(config_file)
    except Exception as e:
        print_red("Could not load configuration file due to the following error:", file=stderr)
        print_red(e, file=stderr)
        return False

    config_schema = get_config_schema()
    validator = SchemaValidator(config_schema)

    if not validator.validate(user_settings):
        print_red("Invalid configuration file!", file=stderr)
        for key in validator.errors:
            print(f"- {key}:", file=stderr)
            for error in validator.errors[key]:
                print("  ", error, file=stderr)
        print(f"Please fix the configuration file located at {CONFIG_FILE_PATH}", file=stderr)
        exit(1)

    config["db_host"] = db_host or user_settings["db_host"]
    config["db_user"] = db_user or user_settings["db_user"]
    config["db_name"] = db_name or user_settings["db_name"]
    config["db_port"] = db_port or user_settings["db_port"]
    config["db_type"] = db_type or user_settings["db_type"]

    return True


def load_config() -> bool:
    global config, creds_file_path

    if creds_file_path != None:
        return

    if not os.path.isfile(CONFIG_FILE_PATH):
        print("It looks like you haven't set Rizpass up.", file=stderr)
        print("You can do so by using the --setup flag", file=stderr)
        print("If you want to use Rizpass in file mode, you can use the --file flag", file=stderr)
        exit(1)

    try:
        config_file = open(CONFIG_FILE_PATH, "r+")
        file_content = config_file.readlines()
        if not file_content or len(file_content) == 0:
            print("Invalid config file!", file=stderr)
            print(f"Please fix the configuration file located at {CONFIG_FILE_PATH}", file=stderr)
            exit(1)
        else:
            config_file.seek(0, 0)
        user_settings: Dict[str, str] = json.load(config_file)

        config_schema = get_config_schema()
        validator = SchemaValidator(config_schema)

        if not validator.validate(user_settings):
            print("Invalid configuration file!", file=stderr)
            for key in validator.errors:
                print(f"- {key}:", file=stderr)
                for error in validator.errors[key]:
                    print("  ", error, file=stderr)
            print(f"Please fix the configuration file located at {CONFIG_FILE_PATH}", file=stderr)
            exit(1)

        config = dict(user_settings)

        return True
    except Exception as e:
        print("Could not load configuration file due to the following error:", file=stderr)
        print(e, file=stderr)
        exit(1)


# def login() -> None:
#     global master_pass, creds_manager, creds_file_path

#     master_pass = getpass("Master Password: ")
#     if creds_file_path != None:
#         creds_manager = FileManager(creds_file_path)
#         return

#     db_config = DbConfig(
#         config["db_host"],
#         config["db_user"],
#         master_pass,
#         config["db_name"],
#         config["db_port"]
#     )
#     if config["db_type"] == "mysql":
#         creds_manager = MysqlManager(db_config)
#     elif config["db_type"] == "mongo":
#         creds_manager = MongoManager(db_config)


def generate_password() -> None:

    pass_len = better_input(
        "Password length (Min: 4): ",
        validator=lambda x:  True if x.isnumeric() and int(x) >= 4 else "Password length must be >= 4 ",
    )

    if pass_len == None:
        return
    pass_len = int(pass_len)

    # uppercase, lowercase, numbers, specials
    uppercase = confirm("Uppercase letters? (Y/N): ")
    lowercase = confirm("Lowercase letters? (Y/N): ")
    numbers = confirm("Numbers? (Y/N): ")
    specials = confirm("Special characters? (Y/N): ")
    print()

    generated_pass = generate_random_password(pass_len, uppercase, lowercase, numbers, specials)

    if not generated_pass:
        print("Could not generate a password! Try again later!")
        return

    print("Generated Password: ", Fore.BLUE + generated_pass + Fore.RESET)

    try:
        pyperclip.copy(generated_pass)
    except Exception as e:
        print_red("The generated password could not be copied to your clipboard due to the following error:", file=stderr)
        print_red(e, file=stderr)
    else:
        print("The generated password has been copied to your clipboard.")

    if confirm("Do you want to add this password (Y/N): "):
        add_credential(generated_pass)


def add_credential(user_password: str = None) -> None:
    ensure_type(user_password, str | None, "user_password", "string | None")

    title = better_input("Title: ")
    if title == None:
        print_red("Aborting operation due to invalid input!", file=stderr)
        return

    username = better_input("(Optional) Username: ", optional=True)
    if username == None:
        username = ""

    email = better_input("(Optional) Email: ", optional=True)
    if email == None:
        email = ""

    password = user_password if user_password else better_input("Password: ", password=True)
    if password == None:
        print_red("Aborting operation due to invalid input!", file=stderr)
        return

    if not confirm("Are you sure you want to add this password (Y/N): ", loose=True):
        return

    salt = generate_salt(16)
    encrypted_title = encrypt_and_encode(master_pass, title, salt)
    encrypted_username = encrypt_and_encode(master_pass, username, salt)
    encrypted_email = encrypt_and_encode(master_pass, email, salt)
    encrypted_password = encrypt_and_encode(master_pass, password, salt)
    encoded_salt = b64encode(salt).decode("ascii")

    creds_manager.add_credential(
        encrypted_title,
        encrypted_username,
        encrypted_email,
        encrypted_password,
        encoded_salt
    )
    print()
    print("Password added successfully!")


def get_credential() -> None:
    # id = int(input("ID: "))
    id = pos_int_input("ID: ")
    if not id:
        print_red("Aborting operation due to invalid input!", file=stderr)
        return

    raw_cred = None

    raw_cred = creds_manager.get_credential(id)

    if raw_cred == None:
        print_yellow("No credential with given id found!")
        return

    cred: Credential = raw_cred.get_credential(master_pass)
    print(cred)
    cred.copy_pass()


def filter_credentials() -> None:
    title_filter = better_input("(Optional) Title should contain: ", optional=True)
    if title_filter == None:
        title_filter = ""

    username_filter = better_input("(Optional) Username should contain: ", optional=True)
    if username_filter == None:
        username_filter = ""

    email_filter = better_input("(Optional) Email should contain: ", optional=True)
    if email_filter == None:
        email_filter = ""

    creds: List[RawCredential] = []

    creds.extend(creds_manager.filter_credentials(title_filter, username_filter, email_filter, master_pass))

    if not creds:
        print_yellow("No credentials meet your given filter.")
        return

    print("Following credentials meet your given filters:")
    for credential in creds:
        print(credential)

    credential.copy_pass()


def get_all_credentials() -> None:
    try:
        raw_creds: List[RawCredential] = []
        raw_creds.extend(creds_manager.get_all_credentials())
        if not raw_creds:
            print_yellow("No credentials stored yet.")
            return

        print_magenta("Printing all credentials...")
        lastCred = None
        for raw_cred in raw_creds:
            lastCred = raw_cred.get_credential(master_pass)
            print(lastCred)
            print()

        if lastCred:
            lastCred.copy_pass()

    except Exception as e:
        print_red("Could not get credentials due to the following error:", file=stderr)
        print_red(e, file=stderr)


def get_all_raw_credentials() -> None:
    raw_creds = creds_manager.get_all_credentials()
    if not raw_creds:
        print_red("No credentials stored yet.", file=stderr)
        return

    print_magenta("Printing all credentials(encrypted and encoded)...")
    for raw_cred in raw_creds:
        print(raw_cred)


def modify_credential() -> None:
    # Later add functionality for changing the password itself
    # id = int(input("ID: "))
    id = pos_int_input("ID: ")
    if not id:
        print_red("Aborting operation due to invalid input!", file=stderr)
        return

    old_cred = creds_manager.get_credential(id).get_credential(master_pass)

    if old_cred == None:
        print_red("No credential with given id exists!", file=stderr)
        return

    print("Leave any field empty if you do not wish to change it")
    new_title = better_input("(Optional) Title: ", optional=True)
    if new_title == None or not new_title.strip():
        new_title = ""

    new_username = better_input("(Optional) Username: ", optional=True)
    if new_username == None or not new_username.strip():
        new_username = ""

    new_email = better_input("(Optional) Email: ", optional=True)
    if new_email == None or not new_email.strip():
        new_email = ""

    new_password = better_input("(Optional) Password: ", password=True, optional=True)
    if new_password == None or not new_password.strip():
        new_password = ""

    if not confirm("Are you sure you want to modify this password (Y/N): "):
        return

    if new_title == new_username == new_email == new_password == "":
        return

    salt = generate_salt(16)

    new_pass = encrypt_and_encode(
        master_pass,
        new_password if new_password else old_cred.password,
        salt
    )
    new_title = encrypt_and_encode(
        master_pass,
        new_title if new_title else old_cred.title,
        salt
    )
    new_email = encrypt_and_encode(
        master_pass,
        new_email if new_email else old_cred.email,
        salt
    )
    new_username = encrypt_and_encode(
        master_pass,
        new_username if new_username else old_cred.username,
        salt
    )

    creds_manager.modify_credential(
        id,
        new_title,
        new_username,
        new_email,
        new_pass,
        b64encode(salt).decode("ascii")
    )

    print()
    print_green("Modified credential successfully!")


def remove_credential() -> None:
    # id = int(input("ID: "))
    id = pos_int_input("ID: ")
    if not id:
        print_red("Aborting operation due to invalid input!", file=stderr)
        return

    if creds_manager.get_credential(id) == None:
        print_red(f"No credential with id: {id} exists!", file=stderr)
        return

    creds_manager.remove_credential(id)

    print()
    print_green("Removed password successfully!")


def remove_all_credentials() -> None:
    for _ in range(2):
        if not confirm("Are you sure you want to remove all stored passwords (Y/N): "):
            return

    if getpass("Re-enter master password: ") != master_pass:
        print("Incorrect password!")
        print("Exiting...")
        exit_app()

    creds_manager.remove_all_credentials()

    print()
    print_green("Removed all passwords successfully!")


def change_masterpass() -> None:
    global creds_manager, master_pass

    if not confirm("Are you sure you want to change your master password (Y/N): "):
        return

    new_masterpass = getpass(
        "Input new master password (Should meet DB Password Requirements): "
    )
    if new_masterpass == master_pass:
        print_red("New master password is the same as the old one!", file=stderr)
        return

    # Change database password
    if creds_manager:
        # TODO: Implement input validation
        if config["db_type"] == "mysql":
            root_user = better_input("Input mysql root username: ")
            root_pass = better_input("Input mysql root password: ", password=True)
            temp_db_manager = MysqlManager(DbConfig(config["db_host"], root_user, root_pass, "", config.get("db_port", None)))
            temp_db_manager.mysql_cursor.execute(
                "ALTER USER %s@'%' IDENTIFIED BY %s;",
                (config["db_user"],  new_masterpass, )
            )

        elif config["db_type"] == "mongo":
            root_user = better_input("Input MongoDB root username: ")
            root_pass = better_input("Input MongoDB root password: ", password=True)

            db_client = MongoClient(
                config["db_host"],
                username=root_user,
                password=root_pass,
                port=config.get("db_port", 27017),
                serverSelectionTimeoutMS=1000,
                connectTimeoutMS=3000,
                socketTimeoutMS=3000,
            )
            db_db = db_client[config["db_name"]]
            db_db.command({
                "updateUser": config["db_user"],
                "pwd": new_masterpass,
            })

            db_client.close()

            print_green("Changed database user's password successfully!")

        creds_manager.close()

        db_config = DbConfig(
            config["db_host"],
            config["db_user"],
            new_masterpass,
            config["db_name"],
            config.get("db_port", None)
        )
        if config["db_type"] == "mysql":
            creds_manager = MysqlManager(db_config)
        elif config["db_type"] == "mongo":
            creds_manager = MongoManager(db_config)

    # Decrypt passwords and encrypt them with new salt and master password
    raw_creds = creds_manager.get_all_credentials()
    for raw_cred in raw_creds:
        old_cred = raw_cred.get_credential(master_pass)
        salt = generate_salt(16)
        new_pass = encrypt_and_encode(
            new_masterpass,
            old_cred.password,
            salt
        )
        new_title = encrypt_and_encode(
            new_masterpass,
            old_cred.title,
            salt
        )
        new_email = encrypt_and_encode(
            new_masterpass,
            old_cred.email,
            salt
        )
        new_username = encrypt_and_encode(
            new_masterpass,
            old_cred.username,
            salt
        )

        creds_manager.modify_credential(
            raw_cred.id,
            new_title,
            new_username,
            new_email,
            new_pass,
            b64encode(salt).decode("ascii")
        )

    print_green("Changed credential's master password successfully!")

    master_pass = new_masterpass


def import_credentials() -> None:
    filename = better_input("Filename: ", validator=lambda x: True if os.path.isfile(x) else "File not found!")
    if filename == None:
        print("Aborting operation due to invalid input!", file=stderr)
        return

    if not os.path.isfile(filename):
        print_red(f"\"{filename}\" does not exist!", file=stderr)
        print_red(f"Aborting operation due to invalid input!", file=stderr)
        return

    file_master_pass: str = getpass("Input master password for file: ")
    file_creds = json.load(open(filename, "r"))

    if not file_creds:
        print("There are no credentials in the file.")

    print("\nBegin importing file credentials...")

    for file_cred in file_creds:

        raw_cred = RawCredential(
            id=file_cred["id"],
            title=file_cred["title"],
            username=file_cred["username"],
            email=file_cred["email"],
            password=file_cred["password"],
            salt=file_cred["salt"],
        )

        salt = generate_salt(16)

        new_cred = raw_cred.get_credential(file_master_pass).get_raw_credential(master_pass, salt)

        creds_manager.add_credential(
            new_cred.title,
            new_cred.username,
            new_cred.email,
            new_cred.password,
            new_cred.salt,
        )

        print_green("Credential added.")
        print()

    print_green("Imported credentials successfully!")


def export_credentials() -> None:
    file_path = better_input("File Path: ")
    file_master_pass = getpass("File Master Password (Optional): ")

    if file_path == None:
        print_red("Aborting operation due to invalid input!", file=stderr)
        return

    raw_creds: List[RawCredential] = creds_manager.get_all_credentials()
    if not raw_creds:
        print("No credentials to export.")
        return

    cred_objs = []

    for raw_cred in raw_creds:
        salt = generate_salt(16)
        cred = raw_cred.get_credential(master_pass).get_raw_credential(file_master_pass, salt)

        cred_objs.append({
            "id": cred.id,
            "title": cred.title,
            "username": cred.username,
            "email": cred.email,
            "password": cred.password,
            "salt": b64encode(salt).decode('ascii'),
        })

    json.dump(cred_objs, open(file_path, "w"))

    print()
    print_green("Exported credentials successfully!")


def clear_console() -> None:
    print("\033c", end="")


def signal_handler(signal, frame):
    print("\n\nExiting due to manual intervention...")
    exit_app(130)


def exit_app(exit_code=0) -> NoReturn:
    creds_manager.close() if creds_manager else None
    exit(exit_code)


def get_list_item_safely(array: List[str], index: str) -> str | None:
    ensure_type(array, list, "array", "list")
    ensure_type(index, int, "index", "int")

    if len(array) <= index:
        return None
    else:
        return array[index]


def print_help(error: bool = False) -> None:
    file = stderr if error else stdout
    print("Usage: rizpass [options]", file=file)
    print("Options:", file=file)
    print("   -h, --help            Prints this help message", file=file)
    print("   -v, --version         Prints the version number", file=file)
    print("   -s, --setup           Setup rizpass", file=file)
    print("   -f, --file <file>     Use file as credential storage", file=file)
    print("   --nocolor             Disable color output", file=file)


def process_args(args: List[str]) -> Dict[str, str]:
    """Processes command line arguments and returns a dictionary of the arguments with their values if possible."""
    ensure_type(args, list, "args", "list")

    ignore_args = {0}

    args_dict = dict({
        "print_version": False,
        "print_help": False,
        "init_setup": False,
        "file_mode": False,
        "file_path": None,
        "color_mode": True,
    })

    for index, arg in enumerate(args):
        if index in ignore_args:
            continue

        elif arg == "--version" or arg == "-v":
            args_dict["print_version"] = True

        elif arg == "--help" or arg == "-h":
            args_dict["print_help"] = True

        elif arg == "--file" or arg == "-f":
            args_dict["file_mode"] = True
            args_dict["file_path"] = get_list_item_safely(args, index + 1)
            if args_dict["file_path"] == None:
                print_red("Invalid file path!", file=stderr)
                exit_app(129)
            ignore_args.add(index + 1)

        elif arg == "--setup" or arg == "-s":
            args_dict["init_setup"] = True

        elif arg == "--nocolor":
            args_dict["color_mode"] = False

        else:
            print_red(f"Invalid argument: {arg}", file=stderr)
            print_help(True)
            exit_app(129)

    return args_dict


def handle_processed_args(options: Dict[str, str]) -> None:
    # Load config from arguments
    set_colored_output(options.get("color_mode"))

    if options.get("print_help"):
        print_help()
        exit_app(0)
    if options.get("print_version"):
        print_license()
        exit_app(0)

    if options.get("init_setup"):
        setup_password_manager()
        exit_app(0)

    global config

    if options.get("file_mode"):
        config["file_path"] = options.get("file_path")
    else:
        exit(1) if not load_db_config() else None

    # Login
    global master_pass, creds_manager

    master_pass = getpass("Master Password: ")

    if config.get("file_path"):
        creds_manager = FileManager(config.get("file_path"))
        return

    db_config = DbConfig(
        config.get("db_host"),
        config.get("db_user"),
        master_pass,
        config.get("db_name"),
        config.get("db_port")
    )

    creds_manager = MysqlManager(db_config) if config.get("db_type") == "mysql" else MongoManager(db_config)


# Handle interruptions
signal.signal(signal.SIGINT, signal_handler)

menu_items: Dict[str, Tuple[str, Callable]] = {
    1: ("Generate a password", generate_password),
    2: ("Add a credential", add_credential),
    3: ("Retrieve credential using id", get_credential),
    4: ("Filter credentials", filter_credentials),
    5: ("List all credentials", get_all_credentials),
    6: ("Modify credential", modify_credential),
    7: ("Remove credential", remove_credential),
    8: ("Remove all credentials", remove_all_credentials),
    9: ("Change master password", change_masterpass),
    10: ("Export credentials to a JSON file", export_credentials),
    11: ("Import credentials from a JSON file", import_credentials),
    12: ("List all raw credentials", get_all_raw_credentials),
    13: ("Exit", exit_app),
}


def print_menu():
    clear_console()
    print((Fore.BLUE if get_colored_output() else '') + "-------------------------------" + (Fore.RESET if get_colored_output() else ''))
    print((Fore.BLUE if get_colored_output() else '') + f"Rizpass {VERSION_NUMBER}" + (Fore.RESET if get_colored_output() else ''))
    print((Fore.BLUE if get_colored_output() else '') + "Mode: " + (Fore.RESET if get_colored_output() else '') +
          (Fore.YELLOW if get_colored_output() else '') + get_mode() + (Fore.RESET if get_colored_output() else ''))
    print()

    for key in menu_items:
        print((Fore.BLUE if get_colored_output() else '') + str(key).ljust(2) +
              (Fore.RESET if get_colored_output() else '') + "  " + menu_items[key][0])
        pass

    print((Fore.BLUE if get_colored_output() else '') + "-------------------------------" + (Fore.RESET if get_colored_output() else ''))


def init():
    handle_processed_args(process_args(argv))
    # load_config()
    # if not load_db_config():
    # exit_app(1)
    # login()

    while True:
        print_menu()
        perform_tasks()


if __name__ == "__main__":
    init()
