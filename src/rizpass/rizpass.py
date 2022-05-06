#!/usr/bin/env python3
from base64 import b64encode
import os
import pyperclip
import json
from getpass import getpass
from sys import exit, argv, stderr
from typing import Callable, List, Dict, NoReturn, Tuple
from cerberus import Validator as SchemaValidator
from pymongo.mongo_client import MongoClient
from colorama import init as color_init, Fore
import signal

from .better_input import confirm, better_input, even_better_input, pos_int_input
from .schemas import get_config_schema
from .passwords import generate_password as generate_random_password, encrypt_and_encode, generate_salt
from .credentials import RawCredential, Credential
from .database_manager import DatabaseManager, DbConfig
from .setup_rizpass import setup_password_manager
from .file_manager import FileManager

CONFIG_FILE_PATH = os.path.expanduser("~/.rizpass.json")
VERSION_NUMBER = 'v0.0.1-alpha'

master_pass:  str = None
db_manager: DatabaseManager = None

creds_file_path: str = None
file_manager: FileManager = None

config: Dict[str, str] = dict()

# TODO: Add requirements for master password

color_init()


def get_mode() -> str:
    if file_manager:
        return "file"
    elif config["db_type"] == "mongo":
        return "mongo"
    else:
        return "mysql"


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


def load_config() -> bool:
    global config

    if not os.path.isfile(CONFIG_FILE_PATH):
        print("It looks like you haven't set Rizpass up.", file=stderr)
        print("You can do so by using the --setup flag", file=stderr)
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


def login() -> None:
    global master_pass, db_manager, creds_file_path, file_manager
    master_pass = getpass("Master Password: ")
    if creds_file_path != None:
        file_manager = FileManager(creds_file_path)
    else:
        db_manager = DatabaseManager(
            config["db_type"],
            DbConfig(
                config["db_host"],
                config["db_user"],
                master_pass,
                config["db_name"],
                config.get("db_port", None)
            )
        )


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
        print(f"{Fore.RED}The generated password could not be copied to your clipboard due to the following error:", file=stderr)
        print(e, Fore.RESET, file=stderr)
    else:
        print("The generated password has been copied to your clipboard.")

    if confirm("Do you want to add this password (Y/N): "):
        add_credential(generated_pass)


def add_credential(user_password: str = None) -> None:
    title = better_input("Title: ")
    if title == None:
        print(f"{Fore.RED}Aborting operation due to invalid input!{Fore.RESET}", file=stderr)
        return

    username = better_input("(Optional) Username: ", optional=True)
    if username == None:
        username = ""

    email = better_input("(Optional) Email: ", optional=True)
    if email == None:
        email = ""

    password = user_password if user_password else better_input("Password: ", password=True)
    if password == None:
        print(f"{Fore.RED}Aborting operation due to invalid input!{Fore.RESET}", file=stderr)
        return

    if not confirm("Are you sure you want to add this password (Y/N): ", loose=True):
        return

    salt = generate_salt(16)
    encrypted_title = encrypt_and_encode(master_pass, title, salt)
    encrypted_username = encrypt_and_encode(master_pass, username, salt)
    encrypted_email = encrypt_and_encode(master_pass, email, salt)
    encrypted_password = encrypt_and_encode(master_pass, password, salt)
    encoded_salt = b64encode(salt).decode("ascii")

    if db_manager:
        db_manager.add_credential(
            encrypted_title,
            encrypted_username,
            encrypted_email,
            encrypted_password,
            encoded_salt
        )
    if file_manager:
        file_manager.add_credential(
            encrypted_title,
            encrypted_username,
            encrypted_email,
            encrypted_password,
            encoded_salt
        )
    print(f"{Fore.GREEN}\nPassword added successfully!{Fore.RESET}")


def get_credential() -> None:
    # id = int(input("ID: "))
    id = pos_int_input("ID: ")
    if not id:
        print(f"{Fore.RED}Aborting operation due to invalid input!{Fore.RESET}", file=stderr)
        return

    raw_cred = None

    if db_manager:
        raw_cred = db_manager.get_credential(id)
    if file_manager:
        raw_cred = file_manager.get_credential(id)

    if raw_cred == None:
        print(f"{Fore.YELLOW}No credential with given id found!{Fore.YELLOW}")
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

    if db_manager:
        creds.extend(db_manager.filter_credentials(title_filter, username_filter, email_filter, master_pass))
    if file_manager:
        creds.extend(file_manager.filter_credentials(title_filter, username_filter, email_filter, master_pass))

    if not creds:
        print(f"{Fore.YELLOW}No credentials meet your given filter.{Fore.RESET}")
        return

    print("Following credentials meet your given filters:")
    for credential in creds:
        print(credential)

    credential.copy_pass()


def get_all_credentials() -> None:
    try:
        raw_creds: List[RawCredential] = []
        if db_manager:
            raw_creds.extend(db_manager.get_all_credentials())
        if file_manager:
            raw_creds.extend(file_manager.get_all_credentials())
        if not raw_creds:
            print(f"{Fore.YELLOW}No credentials stored yet.{Fore.RESET}")
            return

        print(f"{Fore.MAGENTA}Printing all credentials...{Fore.RESET}")
        lastCred = None
        for raw_cred in raw_creds:
            lastCred = raw_cred.get_credential(master_pass)
            print(lastCred)
            print()

        if lastCred:
            lastCred.copy_pass()

    except Exception as e:
        print(f"{Fore.RED}Could not get credentials due to the following error:", file=stderr)
        print(e, Fore.RESET, file=stderr)


def get_all_encrypted_credentials() -> None:
    raw_creds = (db_manager or file_manager).get_all_credentials()
    if not raw_creds:
        print(f"{Fore.RED}No credentials stored yet.{Fore.RESET}", file=stderr)
        return

    print(f"{Fore.MAGENTA}Printing all credentials(encrypted and encoded)...{Fore.RESET}")
    for raw_cred in raw_creds:
        print(raw_cred)


def modify_credential() -> None:
    # Later add functionality for changing the password itself
    # id = int(input("ID: "))
    id = pos_int_input("ID: ")
    if not id:
        print(f"{Fore.RED}Aborting operation due to invalid input!{Fore.RESET}", file=stderr)
        return

    old_cred = (db_manager or file_manager).get_credential(id).get_credential(master_pass)

    if old_cred == None:
        print(f"{Fore.RED}No credential with given id exists!{Fore.RESET}", file=stderr)
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

    (db_manager or file_manager).modify_credential(
        id,
        new_title,
        new_username,
        new_email,
        new_pass,
        b64encode(salt).decode("ascii")
    )

    print(f"{Fore.GREEN}Modified credential successfully!{Fore.RESET}")


def remove_credential() -> None:
    # id = int(input("ID: "))
    id = pos_int_input("ID: ")
    if not id:
        print(f"{Fore.RED}Aborting operation due to invalid input!{Fore.RESET}", file=stderr)
        return

    if (db_manager or file_manager).get_credential(id) == None:
        print(f"{Fore.RED}No credential with id: {id} exists!{Fore.RESET}", file=stderr)
        return

    (db_manager or file_manager).remove_credential(id)
    print(f"{Fore.GREEN}Removed password successfully!{Fore.GREEN}")


def remove_all_credentials() -> None:
    for _ in range(2):
        if not confirm("Are you sure you want to remove all stored passwords (Y/N): "):
            return

    if getpass("Re-enter master password: ") != master_pass:
        print("Incorrect password!")
        print("Exiting...")
        exit_app()

    if db_manager:
        db_manager.remove_all_credentials()
    if file_manager:
        file_manager.remove_all_credentials()

    print(f"{Fore.GREEN}Removed all passwords successfully!{Fore.RESET}")


def change_masterpass() -> None:
    global db_manager, master_pass

    if not confirm("Are you sure you want to change your master password (Y/N): "):
        return

    new_masterpass = getpass(
        "Input new master password (Should meet DB Password Requirements): "
    )
    if new_masterpass == master_pass:
        print(f"{Fore.GREEN}New master password is the same as the old one!{Fore.RESET}")
        return

    # Change database password
    if db_manager:
        # TODO: Implement input validation
        if config["db_type"] == "mysql":
            root_user = better_input("Input mysql root username: ")
            root_pass = better_input("Input mysql root password: ", password=True)  # Implement a better_pass method later using the getpass
            temp_db_manager = DatabaseManager("mysql", DbConfig(config["db_host"], root_user, root_pass, "", config.get("db_port", None)))
            temp_db_manager.mysql_cursor.execute(
                "ALTER USER '%s'@'%' IDENTIFIED BY %s;",
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

            print(f"{Fore.GREEN}Changed database user's password successfully!{Fore.RESET}")

        db_manager.close()

        db_manager = DatabaseManager(
            config.get("db_type", "mysql"),
            DbConfig(
                config["db_host"],
                config["db_user"],
                new_masterpass,
                config["db_name"],
                config.get("db_port", None)
            )
        )

    # Decrypt passwords and encrypt them with new salt and master password
    raw_creds = (db_manager or file_manager).get_all_credentials()
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

        (db_manager or file_manager).modify_credential(
            raw_cred.id,
            new_title,
            new_username,
            new_email,
            new_pass,
            b64encode(salt).decode("ascii")
        )

    print(f"{Fore.GREEN}Changed credential's master password successfully!{Fore.RESET}")

    master_pass = new_masterpass


def import_credentials() -> None:
    filename = better_input("Filename: ", validator=lambda x: True if os.path.isfile(x) else "File not found!")
    if filename == None:
        return
    if db_manager:
        db_manager.import_from_file(master_pass, filename)
    if file_manager:
        file_manager.import_from_file(master_pass, filename)

    print(f"{Fore.GREEN}Imported credentials successfully!{Fore.RESET}")


def export_credentials() -> None:
    file_path = better_input("File Path: ")
    file_master_pass = getpass("File Master Password (Optional): ")

    if file_path == None:
        return
    (db_manager or file_manager).export_to_file(
        file_path,
        master_pass,
        file_master_pass if file_master_pass else master_pass
    )

    print(f"{Fore.GREEN}Exported credentials successfully!{Fore.RESET}")


def clear_console() -> None:
    print("\033c", end="")


def signal_handler(signal, frame):
    print("\n\nExiting due to manual intervention...")
    exit_app(130)


def exit_app(exit_code=0) -> NoReturn:
    db_manager.close() if db_manager else None
    file_manager.close() if file_manager else None
    exit(exit_code)


def print_version():
    print("Rizpass " + VERSION_NUMBER)


def get_list_item_safely(list: List[str], index: str) -> str | None:
    if len(list) <= index:
        return None
    else:
        return list[index]


def handle_args(args: List[str]) -> None:
    global creds_file_path
    ignore_args = {0}

    for index, arg in enumerate(args):
        if index in ignore_args:
            continue

        if "--version" == arg or "-V" == arg:
            print_version()
            exit_app(0)
        elif "--setup" == arg or "-S" == arg:
            setup_password_manager()
            exit_app(0)
        elif "--file" == arg or "-F" == arg:
            creds_file_path = get_list_item_safely(args, index + 1)
            if creds_file_path == None:
                print("Filename cannot be empty!", file=stderr)
                exit_app(129)
            print(f"Using file: {creds_file_path}")
            ignore_args.add(index + 1)
        else:
            print("Unknown argument: " + arg)
            exit_app(129)


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
    12: ("List all credentials (encrypted and encoded)", get_all_encrypted_credentials),
    13: ("Exit", exit_app),
}


def print_menu():
    print(Fore.BLUE + "-------------------------------" + Fore.RESET)
    print(Fore.BLUE + f"Rizpass {VERSION_NUMBER}" + Fore.RESET)
    print(Fore.BLUE + "Mode: " + Fore.RESET + Fore.YELLOW + get_mode() + Fore.RESET)
    print()
    # print(f"{Fore.BLUE}1{Fore.RESET}  Generate a password")
    # print(f"{Fore.BLUE}2{Fore.RESET}  Add a credential")
    # print(f"{Fore.BLUE}3{Fore.RESET}  Retrieve credential using id")
    # print(f"{Fore.BLUE}4{Fore.RESET}  Filter credentials")
    # print(f"{Fore.BLUE}5{Fore.RESET}  List all credentials")
    # print(f"{Fore.BLUE}6{Fore.RESET}  Modify credential")
    # print(f"{Fore.BLUE}7{Fore.RESET}  Remove credential")
    # print(f"{Fore.BLUE}8{Fore.RESET}  Remove all credentials")
    # print(f"{Fore.BLUE}9{Fore.RESET}  Change master password")
    # print(f"{Fore.BLUE}10{Fore.RESET} Export credentials to a JSON file")
    # print(f"{Fore.BLUE}11{Fore.RESET} Import credentials from a JSON file")
    # print(f"{Fore.BLUE}12{Fore.RESET} List all credentials (encrypted and encoded)")
    # print(f"{Fore.BLUE}13{Fore.RESET} Exit")

    for key in menu_items:
        print(Fore.BLUE + str(key).ljust(2) + Fore.RESET + "  " + menu_items[key][0])
        pass

    print(Fore.BLUE + "-------------------------------" + Fore.RESET)


def init():
    handle_args(argv)
    load_config()
    login()

    while True:
        print_menu()
        perform_tasks()
        clear_console()


if __name__ == "__main__":
    init()
