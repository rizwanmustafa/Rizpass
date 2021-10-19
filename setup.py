#!/usr/bin/env python3
from getpass import getpass
from DatabaseManager import DatabaseManager

#TODO:
#1. Split the big method into smaller methods

def setup_password_manager():

    # Login to MySQL
    mysqlRootUserName = input("Input MySQL root username: ")
    mysqlRootPassword = getpass("Input MySQL root password: ")
    dbManager = DatabaseManager("localhost", mysqlRootUserName, mysqlRootPassword)

    # Obtain master password and double check it with user
    for i in range(3):
        masterPassword = getpass("Input new master password (Password should meet MySQL password requirements): ")

        if masterPassword.strip() == "":
            print("Master password cannot be empty or whitespace!")
            continue

        if getpass("Re-enter master password: ") == masterPassword:
            break
        else:
            print("Passwords do not match!\n")

        if i == 2:
            print("3 Incorrect Password Attempts: Exiting!")
            exit()

    # TODO: Get name of custom database
    # Drop database if it exists to prevent problems
    confirmChoice = input(
        "Dropping database 'LocalPasswordManager' if it exists. Are you sure you want to continue? (Y/N)")
    if confirmChoice == "Y" or confirmChoice == "y":
        dbManager.ExecuteRawQuery("DROP DATABASE IF EXISTS LocalPasswordManager;")
    else:
        exit()

    # TODO: Get name of custom user
    # Drop user if it exists to prevent problems
    confirmChoice = input("Dropping user 'passMan'@'localhost' if it exists. Are you sure you want to continue? (Y/N)")
    if confirmChoice == "Y" or confirmChoice == "y":
        dbManager.ExecuteRawQuery("DROP USER IF EXISTS 'passMan'@'localhost';")
    else:
        exit()

    # TODO: Replace names of database and user
    dbManager.ExecuteRawQuery("CREATE DATABASE LocalPasswordManager;")
    dbManager.ExecuteRawQuery("CREATE USER 'passMan'@'localhost' IDENTIFIED BY '{0}';".format(masterPassword))
    dbManager.ExecuteRawQuery("GRANT ALL ON LocalPasswordManager.* TO 'passMan'@'localhost';")
    dbManager.mydb.database = "LocalPasswordManager"
    createTableQuery = """CREATE TABLE Passwords(
        id INT NOT NULL AUTO_INCREMENT,
        title VARCHAR(50) NOT NULL,
        username VARCHAR(50),
        email VARCHAR(50),
        password BLOB NOT NULL,
        salt BLOB NOT NULL,
        PRIMARY KEY( id ));"""
    dbManager.ExecuteRawQuery(createTableQuery)

    # Close the connection to database with root login
    dbManager.dbCursor.close()
    dbManager.mydb.close()

    # TODO: Write to the usersettings.json file


if __name__ == "__main__":
    setup_password_manager()
