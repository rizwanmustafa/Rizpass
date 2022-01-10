#!/usr/bin/env python3
import os
from typing import List
import pyperclip
import json
from getpass import getpass
from sys import exit

from password_crypter import encrypt_password, decrypt_password
from database_manager import DatabaseManager
from setup_localpassman import setup_password_manager
import password_generator

master_password:  str = None
db_manager: DatabaseManager = None


def print_menu():
    menu_itms = [
        "-------------------------------",
        "1. Generate a strong password",
        "2. Add a password",
        "3. Retrieve password using id",
        "4. Filter passwords",
        "5. List all passwords",
        "6. Modify password",
        "7. Remove password",
        "8. Remove all passwords",
        "9. Change master password",
        "10. Export passwords as a JSON file",
        "11. Import passwords from a JSON file",
        "12. Exit",
        "-------------------------------"
    ]

    for menuItm in menu_itms:
        print(menuItm)


def perform_tasks():
    user_choice = input("Please input your choice: ")
    max_limit = 12

    if not user_choice.isnumeric():
        print("Invalid option chosen!")
        return

    user_choice = int(user_choice)

    if user_choice > max_limit and user_choice <= 0:
        print("Invalid option chosen!")
        return

    if user_choice == 1:
        generate_password()
    elif user_choice == 2:
        add_password()
    elif user_choice == 3:
        get_password()
    elif user_choice == 4:
        filter_passwords()
    elif user_choice == 5:
        print_all_passwords()
    elif user_choice == 6:
        modify_password()
    elif user_choice == 7:
        remove_password()
    elif user_choice == 8:
        remove_all_passwords()
    elif user_choice == 9:
        change_masterpassword()
    elif user_choice == 10:
        export_passwords()
    elif user_choice == 11:
        import_passwords()
    elif user_choice == 12:
        exit_app()


def get_user_registration_status() -> bool:
    if not os.path.isfile(os.path.expanduser("~/.localpassman.json")):
        return False

    settingsFile = open(os.path.expanduser("~/.localpassman.json"), "r+")
    userSettings = json.load(settingsFile)

    if userSettings["user_registered"]:
        return True

    return False


def export_passwords():
    filename = input("Filename: ")
    if filename.strip() == "":
        print("Filename cannot be empty or whitespace")
    else:
        db_manager.export_pass_to_json_file(filename)


def import_passwords():
    """
    Imports passwords from a JSON file
    """
    filename = input("Filename: ")
    if filename.strip() == "":
        print("Filename cannot be empty or whitespace")
    else:
        db_manager.import_pass_from_json_file(master_password, filename)


def login():
    global master_password, db_manager
    master_password = getpass("Input your masterpassword: ")
    db_manager = DatabaseManager(
        "localhost", "passMan", master_password, "LocalPasswordManager")


def generate_password():
    passLength = input("Input password length (Min: 8): ")
    if not passLength.isnumeric() or int(passLength) < 8:
        print("Invalid value entered for the length of password!")
    else:
        passLength = int(passLength)

    # uppercase, lowercase, numbers, specials
    uppercase = confirm_user_choice(
        "Should the password contain uppercase letters? (Y/N): ")
    lowercase = confirm_user_choice(
        "Should the password contain lowercase letters? (Y/N): ")
    numbers = confirm_user_choice(
        "Should the password contain numbers? (Y/N): ")
    specials = confirm_user_choice(
        "Should the password contain special characters? (Y/N): ")

    generated_pass = password_generator.generate_password(
        passLength, uppercase, lowercase, numbers, specials)

    if not generated_pass:
        return

    print("Generated Password: ", generated_pass)

    try:
        pyperclip.copy(generated_pass)
        print("The generated password has been copied to your clipboard.")
    except Exception as e:
        print("The generated password could not be copied to your clipboard due to the following error:")
        print(e)

    if not confirm_user_choice("Are you sure you want to add this password (Y/N): "):
        return
    add_password(generated_pass)


def add_password(user_password: str = None):
    title, _, username, email, _ = get_credential_input(
        "Title: ", False, "(Optional) Username: ", "(Optional) Email: ", False)

    if user_password:
        password = user_password
    else:
        password = getpass("Password: ")

    if not confirm_user_choice("Are you sure you want to add this password (Y/N): "):
        return

    salt: bytes = os.urandom(16)
    encrypted_password = encrypt_password(master_password, password, salt)

    db_manager.add_password(title, username, email, encrypted_password, salt)
    print("\nPassword added successfully!")


def print_password(password: List, copy_password=False):
    # Get the data
    id = password[0]
    title = password[1]
    username = password[2]
    email = password[3]
    password = decrypt_password(master_password, password[4], password[5])

    # Print the data
    print("-------------------------------")
    print("ID: {0}".format(id))
    print("Title: {0}".format(title))
    print("Username: {0}".format(username))
    print("Email Address: {0}".format(email))
    print("Password: {0}".format(password))
    print()
    print("-------------------------------")
    if not copy_password:
        return

    try:
        pyperclip.copy(password)
        print("This password has been copied to your clipboard!")
    except Exception as e:
        print("This password could not be copied to your clipboard due to the following error: ")
        print(e)


def print_all_passwords():
    passwords = db_manager.get_all_passwords()

    print("Printing all passwords:")
    for password in passwords:
        print_password(password)


def filter_passwords():
    title_filter, _, username_filter, email_filter, _ = get_credential_input(
        "(Optional) Title should contain: ",
        False,
        "(Optional) Username should contain: ",
        "(Optional) Email should contain: ", False)
    passwords = db_manager.filter_passwords(
        title_filter, username_filter, email_filter)

    print("Following passwords meet your given filters:")
    for password in passwords:
        print_password(password)


def get_password():
    id = get_id_input_from_user()

    password = db_manager.get_password(id)
    if password:
        print_password(password)
    else:
        print("No password with given id found!")


def remove_password():
    id: int = get_id_input_from_user()

    db_manager.remove_password(id)
    print("Removed password successfully!")


def remove_all_passwords():
    for _ in range(2):
        if not confirm_user_choice("Are you sure you want to remove all stored passwords (Y/N): "):
            return

    db_manager.remove_all_passwords()
    print("Removed all passwords successfully!")


def modify_password():
    # Later add functionality for changing the password itself
    id = get_id_input_from_user()

    print("Leave any field empty if you do not wish to change it")
    new_title, _, new_username, new_email, new_password = get_credential_input(
        id=False)

    if not confirm_user_choice("Are you sure you want to modify this password (Y/N): "):
        return

    salt = os.urandom(16) if new_password else None
    encryptedPassword = encrypt_password(
        master_password, new_password, salt) if new_password else None

    if new_title == new_username == new_email == new_password == "":
        return
    else:
        db_manager.modify_password(id,
                                   new_title,
                                   new_username,
                                   new_email,
                                   encryptedPassword,
                                   salt)

    print("Modified password successfully!")


def change_masterpassword():
    if not confirm_user_choice("Are you sure you want to change your masterpassword (Y/N): "):
        return

    newMasterPassword = getpass(
        "Input new masterpassword (Should meet MySQL Password Requirements): ")

    rootUsername = input("Input mysql root username: ")
    rootPassword = getpass("Input mysql root password: ")
    temp_db_manager = DatabaseManager("localhost", rootUsername, rootPassword)
    temp_db_manager.dbCursor.execute(
        "ALTER USER 'passMan'@'localhost' IDENTIFIED BY %s;", (newMasterPassword, ))

    global db_manager, master_password
    db_manager.dbCursor.close()
    db_manager.mydb.close()
    db_manager = DatabaseManager(
        "localhost", "passMan", newMasterPassword, "LocalPasswordManager")
    passwords = db_manager.get_all_passwords()

    # Decrypt passwords and encrypt them with new salt and masterpassword
    for password in passwords:
        salt = os.urandom(16)
        unEncryptedPass = decrypt_password(
            master_password, password[4], password[5])
        newPassword = encrypt_password(
            newMasterPassword, unEncryptedPass,  salt)

        db_manager.modify_password(password[0], "", "", "", newPassword, salt)

    master_password = newMasterPassword


def clear_console():
    os.system('clear')


def exit_app():
    db_manager.dbCursor.close()
    db_manager.mydb.close()
    exit()


def get_id_input_from_user(prompt: None | str = None) -> int:
    id = input("ID: " if prompt == None else prompt)

    if not id.isnumeric() or int(id) <= 0:
        print("Invalid id provided!")

    return int(id)


def get_credential_input(title: bool | str = True,
                         id: bool | str = True,
                         username: bool | str = True,
                         email: bool | str = True,
                         password: bool | str = True,
                         no_validation: bool = True) -> dict:
    """
    Set a parameter to True if you want to get its input from user and want the default prompt.
    If you want a custom prompt, set the parameter to a string of custom prompt
    """
    # TODO: Validate input from user
    # TODO: Raise an exception when recieve invalid input from the user

    if id != None and id != False:
        id = input("ID: " if id == True else id)

        if id.strip() == "" and no_validation == False:
            return  # Raise an exception later

        if not id.isnumeric() or int(id) <= 0:
            print("Invalid id provided!")
            return  # Raise exception later

    else:
        id = None

    if title != None and title != False:
        title = input("Title: " if title == True else title)

        if title.strip() == "" and no_validation == False:
            return  # Raise an exception later

    else:
        title = None

    if username != None and username != False:
        username = input("Username: " if username == True else username)

        if title.strip() == "" and no_validation == False:
            return  # Raise an exception later
    else:
        username = None

    if email != None and email != False:
        email = input("Email: " if email == True else email)

        if title.strip() == "" and no_validation == False:
            return  # Raise an exception later
    else:
        email = None

    if password != None and password != False:
        password = getpass("Password: " if password == True else password)
        if password.strip() == "" and no_validation == False:
            return  # Raise an exception later
    else:
        password = None

    return (title, id, username, email, password)


def confirm_user_choice(prompt: str):
    """
    Returns true if user input 'y' or 'Y' after the prompt
    """
    confirm_choice = input(prompt)
    return confirm_choice.upper() == "Y"


class Credential:
    def __init__(self, *args) -> None:
        # If we are given an array, process it. Else process the separate parameters
        pass_object = args[0] if len(args) == 1 else args

        self.id = pass_object[0]
        self.title = pass_object[1]
        self.username = pass_object[2]
        self.email = pass_object[3]
        self.password = pass_object[4]

    def __str__(self):
        print("-------------------------------")
        print("ID: {0}".format(self.id))
        print("Title: {0}".format(self.title))
        print("Username: {0}".format(self.username))
        print("Email Address: {0}".format(self.email))
        print("Password: {0}".format(self.password))
        print("-------------------------------")

    def copy_pass(self):
        try:
            pyperclip.copy(self.password)
            print("This password has been copied to your clipboard!")
        except Exception as e:
            print(
                "This password could not be copied to your clipboard due to the following error: ")
            print(e)


if __name__ == "__main__":

    while True:
        print(Credential(12, "Title", "Username", "Email", "password"))
        clear_console()
        if not master_password:
            if get_user_registration_status():
                login()
                continue
            print("It seems like you haven't set localpassman up!")
            setup_password_manager()
            clear_console()

        print_menu()
        perform_tasks()
        input("\nPress Enter to continue...")
