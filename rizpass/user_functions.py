from sys import stderr
from typing import Callable, List
from base64 import b64encode
from getpass import getpass
import pyperclip
import os
import json
from typing import Union

from .better_input import better_input, confirm, pos_int_input
from .validator import ensure_type
from .output import print_red, print_colored, print_green, print_yellow, print_magenta, format_colors
from .credentials import Credential, RawCredential
from .misc import print_strong_pass_guidelines

config: dict = dict()
master_pass = ""
creds_manager = None


def exit_app():
    pass


def generate_password() -> None:
    from .passwords import generate_password as generate_random_password, follows_password_requirements

    MIN_LENGTH = 1
    pass_len = better_input(
        f"Password length (Min: {MIN_LENGTH}): ",
        validator=lambda x:  True if x.isnumeric() and int(x) >= MIN_LENGTH else f"Password length must be >= {MIN_LENGTH} ",
    )

    if pass_len == None:
        return
    pass_len = int(pass_len)

    # uppercase, lowercase, digits, specials
    uppercase = confirm("Uppercase letters? [Y/n]: ", True)
    lowercase = confirm("Lowercase letters? [Y/n]: ", True)
    digits = confirm("Digits? [Y/n]: ", True)
    specials = confirm("Special characters? [Y/n]: ", True)
    print()

    generated_pass = generate_random_password(pass_len, uppercase, lowercase, digits, specials)

    if not generated_pass:
        print_red("Could not generate a password! Try again later!", file=stderr)
        return

    if not follows_password_requirements(generated_pass)[0]:
        print_red("This password does not follow the strong password requirements!")
        print_red("If you want to generate a strong password, try out the strong password generation menu item.")

    print_colored(f"Generated Password: {{blue}}{generated_pass}{{reset}}")

    if not pyperclip.is_available():
        print_red("The generated password can not be copied to your clipboard because pyperclip is not available!", file=stderr)
        print_red("Please copy the password manually.", file=stderr)
    elif confirm("Copy generated password to clipboard? [Y/n] ", True):
        try:
            pyperclip.copy(generated_pass)
        except Exception as e:
            print_red("The generated password could not be copied to your clipboard due to the following error:", file=stderr)
            print_red(e, file=stderr)
        else:
            print("The generated password has been copied to your clipboard.")

    if confirm("Do you want to add this password [Y/n]: ", True):
        add_credential(generated_pass)


def generate_strong_password() -> None:
    from .passwords import generate_password as generate_random_password, follows_password_requirements

    MIN_LENGTH = 16
    pass_len = better_input(
        f"Password length (Min: {MIN_LENGTH}, Rec: 32): ",
        validator=lambda x:  True if x.isnumeric() and int(x) >= MIN_LENGTH else f"Password length must be >= {MIN_LENGTH} ",
    )

    if pass_len == None:
        return
    pass_len = int(pass_len)

    print()

    generated_pass = ""
    for _ in range(10):
        generated_pass = generate_random_password(pass_len, True, True, True, True)
        if follows_password_requirements(generated_pass)[0]:
            break
    else:
        print_red("Could not generate a password! Failed 10 tries! Try again later!", file=stderr)
        return

    if not generated_pass:
        print_red("Could not generate a password! Try again later!", file=stderr)
        return

    print_colored(f"Generated Password: {{blue}}{generated_pass}{{reset}}")

    if not pyperclip.is_available():
        print_red("The generated password can not be copied to your clipboard because pyperclip is not available!", file=stderr)
        print_red("Please copy the password manually.", file=stderr)
    elif confirm("Copy generated password to clipboard? [Y/n] ", True):
        try:
            pyperclip.copy(generated_pass)
        except Exception as e:
            print_red("The generated password could not be copied to your clipboard due to the following error:", file=stderr)
            print_red(e, file=stderr)
        else:
            print("The generated password has been copied to your clipboard.")

    if confirm("Do you want to add this password [Y/n]: ", True):
        add_credential(generated_pass)


def add_credential(user_password: str = None) -> None:
    from . passwords import generate_salt, encrypt_and_encode
    ensure_type(user_password, Union[str, None], "user_password", "string | None")

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

    if not confirm("Are you sure you want to add this password [Y/n]: ", loose=True):
        return

    salt = generate_salt(16)
    encrypted_title = encrypt_and_encode(master_pass, title, salt)
    encrypted_username = encrypt_and_encode(master_pass, username, salt)
    encrypted_email = encrypt_and_encode(master_pass, email, salt)
    encrypted_password = encrypt_and_encode(master_pass, password, salt)
    encoded_salt = b64encode(salt).decode("ascii")

    print()
    try:
        creds_manager.add_credential(
            encrypted_title,
            encrypted_username,
            encrypted_email,
            encrypted_password,
            encoded_salt
        )
    except Exception as e:
        print_red("Could not add credential due to the following error:", file=stderr)
        print_red(e, file=stderr)
    else:
        print_green("Password added successfully!")


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

    try:
        cred: Credential = raw_cred.get_credential(master_pass)
    except Exception as e:
        print_red("Could not get credential due to the following error:", file=stderr)
        print_red(e, file=stderr)
        return

    print(cred)
    if not pyperclip.is_available():
        print_red("The password can not be copied to your clipboard because pyperclip is not available!", file=stderr)
        print_red("Please copy the password manually.", file=stderr)
    else:
        confirm("Copy password to clipboard? [Y/n]: ", True) and cred.copy_pass()


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

    try:
        creds.extend(creds_manager.filter_credentials(title_filter, username_filter, email_filter, master_pass))
    except Exception as e:
        print_red("Could not filter credentials due to the following error:", file=stderr)
        print_red(e, file=stderr)
        return

    if not creds:
        print_yellow("No credentials meet your given filter.")
        return

    print("Following credentials meet your given filters:")
    for credential in creds:
        print(credential)


def get_all_credentials() -> None:
    raw_creds: List[RawCredential] = []
    try:
        raw_creds.extend(creds_manager.get_all_credentials())
    except Exception as e:
        print_red("Could not get all credentials due to the following error:", file=stderr)
        print_red(e, file=stderr)
        return

    if not raw_creds:
        print_yellow("No credentials stored yet.")
        return

    print_magenta("Printing all credentials...")
    for raw_cred in raw_creds:
        try:
            cred = raw_cred.get_credential(master_pass)
        except Exception as e:
            print_red("Could not get credential due to the following error:", file=stderr)
            print_red(e, file=stderr)
            continue

        print(cred)
        print()


def get_all_raw_credentials() -> None:
    try:
        raw_creds = creds_manager.get_all_credentials()
    except Exception as e:
        print_red("Could not get all credentials due to the following error:", file=stderr)
        print_red(e, file=stderr)
        return

    if not raw_creds:
        print_red("No credentials stored yet.", file=stderr)
        return

    print_magenta("Printing all credentials(encrypted and encoded)...")
    for raw_cred in raw_creds:
        print(raw_cred)


def modify_credential() -> None:
    # Later add functionality for changing the password itself
    # id = int(input("ID: "))

    from .passwords import generate_salt,  encrypt_and_encode
    id = pos_int_input("ID: ")
    if not id:
        print_red("Aborting operation due to invalid input!", file=stderr)
        return

    try:
        old_cred = creds_manager.get_credential(id).get_credential(master_pass)
    except Exception as e:
        print_red("Could not get credential due to the following error:", file=stderr)
        print_red(e, file=stderr)
        return

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

    if not confirm("Are you sure you want to modify this password [Y/n]: ", True):
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

    try:
        creds_manager.modify_credential(
            id,
            new_title,
            new_username,
            new_email,
            new_pass,
            b64encode(salt).decode("ascii")
        )
    except Exception as e:
        print_red("Could not modify credential due to the following error:", file=stderr)
        print_red(e, file=stderr)
        return

    print()
    print_green("Modified credential successfully!")


def remove_credential() -> None:
    # id = int(input("ID: "))
    id = pos_int_input("ID: ")
    if not id:
        print_red("Aborting operation due to invalid input!", file=stderr)
        return

    try:
        cred = creds_manager.get_credential(id)
    except Exception as e:
        print_red("Could not get credential due to the following error:", file=stderr)
        print_red(e, file=stderr)
        return

    if cred == None:
        print_red(f"No credential with id: {id} exists!", file=stderr)
        return

    try:
        creds_manager.remove_credential(id)
    except Exception as e:
        print_red("Could not remove credential due to the following error:", file=stderr)
        print_red(e, file=stderr)
        return

    print()
    print_green("Removed password successfully!")


def remove_all_credentials() -> None:
    for _ in range(2):
        if not confirm("Are you sure you want to remove all stored passwords [y/N]: "):
            return

    if getpass("Re-enter master password: ") != master_pass:
        print("Incorrect password!")
        print("Exiting...")
        exit_app()

    try:
        creds_manager.remove_all_credentials()
    except Exception as e:
        print_red("Could not remove all credentials due to the following error:", file=stderr)
        print_red(e, file=stderr)
        return

    print()
    print_green("Removed all passwords successfully!")


def change_masterpass() -> None:
    from .passwords import generate_salt, encrypt_and_encode, follows_password_requirements
    global creds_manager, master_pass, config

    if not confirm("Are you sure you want to change your master password [y/N]: "):
        return

    print()
    print_strong_pass_guidelines()
    print()

    new_masterpass = ""
    while new_masterpass == "" or new_masterpass == master_pass or not follows_password_requirements(new_masterpass)[0]:
        new_masterpass = getpass(
            "Input new master password (Should meet DB Password Requirements): "
        )
        if new_masterpass.replace(" ", "") == "":
            print_red("Master password cannot be empty!", file=stderr)
            new_masterpass = ""
        elif new_masterpass == master_pass:
            print_red("New master password is the same as the old one!", file=stderr)
        elif not follows_password_requirements(master_pass)[0]:
            print_red("Master password does not follow the guidelines!")
            if confirm(format_colors("Are you {red}SURE{reset} you want to continue? [{red}y{reset}/{green}N{reset}] ")):
                break

    # Change database password
    if config.get("db_type", None):
        # TODO: Implement input validation
        from .database_manager import DbConfig
        if config["db_type"] == "mysql":
            from .database_manager import MysqlManager
            root_user = better_input("Input mysql root username: ")
            root_pass = better_input("Input mysql root password: ", password=True)
            temp_db_manager = MysqlManager(DbConfig(config["db_host"], root_user, root_pass, "", config.get("db_port", None)))
            temp_db_manager.mysql_cursor.execute(
                "ALTER USER %s@'%' IDENTIFIED BY %s;",
                (config["db_user"],  new_masterpass, )
            )

        elif config["db_type"] == "mongo":
            from .database_manager import MongoManager
            from pymongo.mongo_client import MongoClient

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
    from .passwords import generate_salt
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
    from .passwords import generate_salt
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


def copy_password() -> None:
    if not pyperclip.is_available():
        print()
        print_red("Pyperclip is not available on your system. Please install it to use this feature.", file=stderr)
        return

    id = better_input("Credential ID: ")
    if id == None:
        print_red("Aborting operation due to invalid input!", file=stderr)
        return

    id = int(id)

    try:
        raw_cred = creds_manager.get_credential(id)
    except Exception as e:
        print_red(f"Could not get credential due to the following error:", file=stderr)
        print_red(e, file=stderr)
        return

    if not raw_cred:
        print_red("Credential not found!", file=stderr)
        return

    raw_cred.copy_pass(master_pass)


def password_checkup() -> None:
    from .passwords import follows_password_requirements
    try:
        raw_creds = creds_manager.get_all_credentials()
    except Exception as e:
        print_red("Could not get all credentials due to the following error:", file=stderr)
        print_red(e, file=stderr)
        return

    if not raw_creds:
        print("No credentials to check.")
        return

    duplicate_passwords = dict()
    weak_passwords = dict()

    print_strong_pass_guidelines()
    print()

    duplicate_num = weak_num = 0

    for raw_cred in raw_creds:
        cred = raw_cred.get_credential(master_pass)
        if cred.password in duplicate_passwords:
            duplicate_num += 1
            duplicate_passwords[cred.password].append(cred.id)
        else:
            duplicate_passwords[cred.password] = [cred.id]

        if not follows_password_requirements(cred.password)[0]:
            weak_num += 1
            weak_passwords[cred.id] = cred.password

    print()

    for id in duplicate_passwords:
        if len(duplicate_passwords[id]) == 1:
            continue

        creds_ids_str = ", ".join(str(id) for id in duplicate_passwords[id])
        print_colored(f"Password {{red}}{id}{{reset}} is used by multiple credentials: {{red}}{creds_ids_str}{{reset}}")

    for id in weak_passwords:
        print_colored(f"Password {{red}}{weak_passwords[id]}{{reset}} for credential {{red}}{id}{{reset}} does not follow password guidelines.")

    if weak_num == 0 and duplicate_num == 0:
        print_green("Password checkup successful!")
        return

    print()

    if duplicate_num == 0:
        print_green("No duplicate passwords found!")
    else:
        print_colored(f"{{red}}{duplicate_num}{{reset}} duplicate passwords found!")

    if weak_num == 0:
        print_green("No weak passwords found!")
    else:
        print_colored(f"{{red}}{weak_num}{{reset}} weak passwords found!")

    print("Please address these issues ASAP!")


def init(master_pass_param: str, exit_app_param: Callable, config_param: dict, creds_manager_param) -> None:
    global master_pass, exit_app, config, creds_manager

    master_pass = master_pass_param
    exit_app = exit_app_param
    config = config_param
    creds_manager = creds_manager_param
