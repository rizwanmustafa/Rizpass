#!/usr/bin/env python3
import os
import pyperclip
import json
from getpass import getpass
from sys import exit

from PasswordCrypter import encrypt_password, decrypt_password
from DatabaseManager import DatabaseManager
from setup import setup_password_manager
import PasswordGenerator

masterPassword:  str = None
dbManager: DatabaseManager = None


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
        dbManager.ExportPasswordsToJSONFile(filename)


def import_passwords():
    """
    Imports passwords from a JSON file
    """
    filename = input("Filename: ")
    if filename.strip() == "":
        print("Filename cannot be empty or whitespace")
    else:
        dbManager.ImportPasswordsFromJSONFile(masterPassword, filename)


def login():
    global masterPassword, dbManager
    masterPassword = getpass("Input your masterpassword: ")
    dbManager = DatabaseManager(
        "localhost", "passMan", masterPassword, "LocalPasswordManager")


def generate_password():
    passLength = input("Input password length (Min: 8): ")
    if not passLength.isnumeric() or int(passLength) < 8:
        print("Invalid value entered for the length of password!")
    else:
        passLength = int(passLength)

    # uppercase, lowercase, numbers, specials
    uppercase = input("Should the password contain uppercase letters? (Y/N): ")
    if uppercase == "Y" or uppercase == "y":
        uppercase = True
    else:
        uppercase = False

    lowercase = input("Should the password contain lowercase letters? (Y/N): ")
    if lowercase == "Y" or lowercase == "y":
        lowercase = True

    numbers = input("Should the password contain numbers? (Y/N): ")
    if numbers == "Y" or numbers == "y":
        numbers = True
    else:
        numbers = False

    specials = input("Should the password contain special characters? (Y/N): ")
    if specials == "Y" or specials == "y":
        specials = True
    else:
        specials = False

    generatedPassword = PasswordGenerator.generate_password(
        passLength, uppercase, lowercase, numbers, specials)

    if generatedPassword:
        print("Your generated password is: ", generatedPassword)
        try:
            pyperclip.copy(generatedPassword)
            print("The generated password has been copied to your clipboard")
        except Exception as e:
            print(
                "The generated password could not be copied to your clipboard due to the following error:")
            print(e)
        addPass = input("Do you want to add this password (Y/N): ")
        if addPass == "Y" or addPass == "y":
            add_password(generatedPassword)


def add_password(userPassword: str = None):
    title = input("Input password title: ")
    username = input("Input username (Optional): ")
    email = input("Input email address (Optional): ")
    password = ""
    if userPassword:
        password = userPassword
    else:
        password = getpass("Input your password: ")

    confirmation = input("Are you sure you want to add this password (Y/N): ")
    if not confirmation == "Y" and not confirmation == "y":
        return

    salt: bytes = os.urandom(16)
    encryptedPassword = encrypt_password(masterPassword, password, salt)

    dbManager.add_password(title, username, email, encryptedPassword, salt)
    print("Password added successfully!")


def print_password(password):
    # Get the data
    id = password[0]
    title = password[1]
    username = password[2]
    email = password[3]
    password = decrypt_password(masterPassword, password[4], password[5])

    # Print the data
    print("-------------------------------")
    print("ID: {0}".format(id))
    print("Title: {0}".format(title))
    print("Username: {0}".format(username))
    print("Email Address: {0}".format(email))
    print("Password: {0}".format(password))
    print()
    try:
        pyperclip.copy(password)
        print("This password has been copied to your clipboard!")
    except Exception as e:
        print("This password could not be copied to your clipboard due to the following error: ")
        print(e)
    print("-------------------------------")


def print_all_passwords():
    passwords = dbManager.get_all_passwords()

    print("Printing all passwords:")
    for password in passwords:
        print_password(password)


def filter_passwords():
    titleFilter = input("Input title filter (Optional): ")
    usernameFilter = input("Input username filter (Optional): ")
    emailFilter = input("Input email filter (Optional): ")

    passwords = dbManager.filter_passwords(
        titleFilter, usernameFilter, emailFilter)

    print("Following passwords meet your given filters:")
    for password in passwords:
        print_password(password)


def get_password():
    id = input("Input password id: ")

    if not id.isnumeric():
        print("Invalid id provided!")
        return

    password = dbManager.get_password(int(id))
    if password:
        print_password(password)
    else:
        print("No password with given id found!")


def remove_password():
    id = input("Input password id: ")

    if not id.isnumeric():
        print("Invalid id provided!")
        return

    id = int(id)

    if id < 0:
        print("Invalid id provided!")
        return

    dbManager.remove_password(int(id))
    print("Removed password successfully!")


def remove_all_passwords():
    confirmChoice = input(
        "Are you sure you want to remove all stored passwords (Y/N): ")
    if confirmChoice == "Y" or confirmChoice == "y":
        dbManager.remove_all_passwords()
        print("Removed all passwords successfully!")


def modify_password():
    # Later add functionality for changing the password itself
    id = input("Input password id: ")
    print("Leave any field empty if you do not wish to change it")
    new_title = input("Input new title: ")
    new_username = input("Input new username: ")
    new_email = input("Input new email: ")
    new_password = getpass("Input new password: ")

    confirm_choice = input(
        "Are you sure you want to modify this password (Y/N): ")
    if not confirm_choice == "Y" and not confirm_choice == "y":
        return

    salt = os.urandom(16)
    encryptedPassword = encrypt_password(
        masterPassword, new_password, salt) if new_password else None

    if new_title == new_username == new_email == new_password == "":
        return
    else:
        dbManager.modify_password(int(id),
                                  new_title,
                                  new_username,
                                  new_email,
                                  encryptedPassword if new_password else None,
                                  salt if new_password else None)

    print("Modified password successfully!")


def change_masterpassword():
    newMasterPassword = getpass(
        "Input new masterpassword (Should meet MySQL Password Requirements): ")

    rootUsername = input("Input mysql root username: ")
    rootPassword = getpass("Input mysql root password: ")
    temp_db_manager = DatabaseManager("localhost", rootUsername, rootPassword)
    temp_db_manager.dbCursor.execute(
        "ALTER USER 'passMan'@'localhost' IDENTIFIED BY %s;", (newMasterPassword, ))

    global dbManager, masterPassword
    dbManager.dbCursor.close()
    dbManager.mydb.close()
    dbManager = DatabaseManager(
        "localhost", "passMan", newMasterPassword, "LocalPasswordManager")
    passwords = dbManager.get_all_passwords()

    # Decrypt passwords and encrypt them with new salt and masterpassword
    for password in passwords:
        salt = os.urandom(16)
        unEncryptedPass = decrypt_password(
            masterPassword, password[4], password[5])
        newPassword = encrypt_password(
            newMasterPassword, unEncryptedPass,  salt)

        dbManager.modify_password(password[0], "", "", "", newPassword, salt)

    masterPassword = newMasterPassword


def clear_console():
    os.system('clear')


def exit_app():
    dbManager.dbCursor.close()
    dbManager.mydb.close()
    exit()


def get_input_from_user(title: str = None,  id: str = None, username: str = None, email: str = None, password: str = None):
    # Set a parameter to True if you want to get its input from user and want the default prompt. Other wise set the parameter to your custom prompt

    if title != None:
        title = input("Password Title: " if title == True else title)
    if id != None:
        id = input("Password ID: " if id == True else id)
    if username != None:
        username = input("Password Username: " if username ==
                         True else username)
    if email != None:
        email = input("Password Email: " if email == True else email)
    if password != None:
        password = getpass("Password: " if password == True else password)

    return (title, id, username, email, password)


if __name__ == "__main__":

    while True:
        if not masterPassword:
            if get_user_registration_status():
                login()
                continue
            print("It seems like you haven't set localpassman up!")
            setup_password_manager()
            clear_console()

        print_menu()
        perform_tasks()
        input("\nPress Enter to continue...")
        clear_console()
