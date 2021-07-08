# Things to do:
# Implement inputting passwords in terminal safely
# Able to copy selected password to the clipboard

import os
import pyperclip
import json

from PasswordCrypter import encrypt_password, decrypt_password
from DatabaseManager import DatabaseManager
import PasswordGenerator 

masterPassword:  str = None
dbManager : DatabaseManager = None

def PrintMenu():
	if not masterPassword:
		if GetUserRegistrationStatus(): Login()
		else: SetupPasswordManager()
		ClearConsole()

	menuItms = [
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

	for menuItm in menuItms: print(menuItm)

	userChoice = input("Please input your choice: ")
	if not userChoice.isnumeric(): print("Invalid option chosen!")
	else: userChoice = int(userChoice)

	if userChoice == 1: GeneratePassword()
	elif userChoice == 2: AddPassword()
	elif userChoice == 3: GetPassword()
	elif userChoice == 4: FilterPasswords()
	elif userChoice == 5: PrintAllPasswords()
	elif userChoice == 6: ModifyPassword()
	elif userChoice == 7: RemovePassword()
	elif userChoice == 8: RemoveAllPasswords()
	elif userChoice == 9: ChangeMasterPassword()
	elif userChoice == 10: dbManager.ExportPasswordsToJSONFile("passwords.json")
	elif userChoice == 11: dbManager.ImportPasswordsFromJSONFile("passwords.json")
	elif userChoice == 12: Exit()

	input("Press Enter to continue...")
	ClearConsole()

def GetUserRegistrationStatus() -> bool:
	settingsFile = open("userdata.json", "r+")
	userSettings = json.load(settingsFile)

	if userSettings["userRegistered"]: return True
	else: return False

def SetUserRegistrationStatus(status : bool) -> bool:
	settingsFile = open("userdata.json", "w")
	userSettings = {
		"userRegistered": status
	}

	json.dump(userSettings, settingsFile)

def SetupPasswordManager():
	global dbManager, masterPassword

	mysqlRootUserName = input("Input MySQL root username: ")
	mysqlRootPassword = input("Input MySQL root password: ")
	dbManager = DatabaseManager("localhost", mysqlRootUserName, mysqlRootPassword)
	masterPassword = input("Input new master password (Password should meet MySQL password requirements): ")

	# Drop database if it exists to prevent problems
	confirmChoice = input("Dropping database 'LocalPasswordManager' if it exists. Are you sure you want to continue? (Y/N)")
	if confirmChoice == "Y" or confirmChoice == "y":
		dbManager.ExecuteRawQuery("DROP DATABASE IF EXISTS LocalPasswordManager;")
	else:
		exit()

	# Drop user if it exists to prevent problems
	confirmChoice = input("Dropping user 'passMan'@'localhost' if it exists. Are you sure you want to continue? (Y/N)")
	if confirmChoice == "Y" or confirmChoice == "y":
		dbManager.ExecuteRawQuery("DROP USER IF EXISTS 'passMan'@'localhost';")
	else:
		exit()

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

	dbManager = DatabaseManager("localhost", "passMan", masterPassword, "LocalPasswordManager")
	SetUserRegistrationStatus(True)

def Login():
	global masterPassword, dbManager
	masterPassword = input("Input your masterpassword: ")
	dbManager = DatabaseManager("localhost", "passMan", masterPassword, "LocalPasswordManager")

def GeneratePassword():
	passLength = input("Input password length (Min: 8): ")
	if not passLength.isnumeric() or int(passLength) < 8: print("Invalid value entered for the length of password!")
	else: passLength = int(passLength)

	# uppercase, lowercase, numbers, specials	
	uppercase = input("Should the password contain uppercase letters? (Y/N): ")
	if uppercase == "Y" or uppercase == "y": uppercase = True
	else : uppercase = False

	lowercase = input("Should the password contain lowercase letters? (Y/N): ")
	if lowercase == "Y" or lowercase == "y": lowercase= True
	

	numbers = input("Should the password contain numbers? (Y/N): ")
	if numbers== "Y" or numbers== "y": numbers= True
	else : numbers= False

	specials = input("Should the password contain special characters? (Y/N): ")
	if specials== "Y" or specials== "y": specials= True
	else : specials = False

	generatedPassword = PasswordGenerator.GeneratePassword(passLength,uppercase, lowercase, numbers, specials)

	if generatedPassword:
		print("Your generated password is: ", generatedPassword)
		pyperclip.copy(generatedPassword)
		print("The generated password has been copied to your clipboard")
		addPass = input("Do you want to add this password (Y/N): ")
		if addPass == "Y" or addPass == "y":
			AddPassword(generatedPassword)

def AddPassword(userPassword:str = None):
	title = input("Input password title: ")
	username = input("Input username (Optional): ")
	email = input("Input email address (Optional): ")
	password = ""
	if userPassword: password = userPassword
	else: password = input("Input your password: ") # Later import a package to add passwords securely

	confirmation = input("Are you sure you want to add this password (Y/N): ")
	if not confirmation == "Y" and not confirmation == "y":
		return 

	salt : bytes = os.urandom(16)
	encryptedPassword = encrypt_password(masterPassword, password, salt)

	dbManager.AddPassword(title, username, email, encryptedPassword, salt)
	print("Password added successfully!")

def PrintPassword(password):
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
	pyperclip.copy(password)
	print("This password has been copied to your clipboard!")
	print("-------------------------------")

def PrintAllPasswords():
	passwords = dbManager.GetAllPasswords()

	print("Printing all passwords:")
	for password in passwords:
		PrintPassword(password)

def FilterPasswords():
	titleFilter = input("Input title filter (Optional): ")
	usernameFilter = input("Input username filter (Optional): ")
	emailFilter = input("Input email filter (Optional): ")

	passwords = dbManager.FilterPasswords(titleFilter, usernameFilter, emailFilter)

	print("Following passwords meet your given filters:")
	for password in passwords:
		PrintPassword(password)

def GetPassword():
	id = input("Input password id: ")

	if not id.isnumeric():
		print("Invalid id provided!")
		return
	
	password = 	dbManager.GetPassword(int(id))
	if password:
		PrintPassword(password)
	else:
		print("No password with given id found!")

def RemovePassword():
	id = input("Input password id: ")

	if not id.isnumeric():
		print("Invalid id provided!")
		return
	
	dbManager.RemovePassword(int(id))
	print("Removed password successfully!")

def RemoveAllPasswords():
	confirmChoice = input("Are you sure you want to remove all stored passwords (Y/N): ")
	if confirmChoice == "Y" or confirmChoice == "y":
		dbManager.RemoveAllPasswords()
		print("Removed all passwords successfully!")

def ModifyPassword():
	# Later add functionality for changing the password itself
	id = input("Input password id: ")
	print("Leave any field empty if you do not wish to change it")
	newTitle = input("Input new title: ")
	newUsername = input("Input new username: ")
	newEmail = input("Input new email: ")
	newPassword = input("Input new password: ")

	confirmChoice = input("Are you sure you want to modify this password (Y/N): ")
	if not confirmChoice == "Y" and not confirmChoice == "y": return

	salt = os.urandom(16)
	encryptedPassword  = encrypt_password(masterPassword,newPassword, salt)

	if newTitle == newUsername == newEmail == newPassword == "": return
	else:
		dbManager.ModifyPassword(int(id), newTitle, newUsername, newEmail, encryptedPassword if newPassword else None, salt if salt else None)

	print("Modified password successfully!")
	

def ChangeMasterPassword():
	newMasterPassword = input("Input new masterpassword (Should meet MySQL Password Requirements): ")

	rootUsername = input("Input mysql root username: ")
	rootPassword = input("Input mysql root password: ")
	anotherDBManager = DatabaseManager("localhost", rootUsername, rootPassword)
	anotherDBManager.dbCursor.execute("ALTER USER 'passMan'@'localhost' IDENTIFIED BY %s;", (newMasterPassword, ))

	global dbManager, masterPassword
	dbManager.dbCursor.close()
	dbManager.mydb.close()
	dbManager = DatabaseManager("localhost", "passMan", newMasterPassword, "LocalPasswordManager")
	passwords =	dbManager.GetAllPasswords() 

	# Decrypt passwords and encrypt them with new salt and masterpassword
	for password in passwords:
		salt = os.urandom(16)
		unEncryptedPass = decrypt_password(masterPassword, password[4], password[5])
		newPassword = encrypt_password(newMasterPassword,unEncryptedPass,  salt)

		dbManager.ModifyPassword(password[0], "", "","", newPassword, salt)

	masterPassword = newMasterPassword

def ClearConsole():
	command = 'clear'
	if os.name in ('nt', 'dos'):  # If Machine is running on Windows, use cls
		command = 'cls'
	os.system(command)

def Exit():
	dbManager.dbCursor.close()
	dbManager.mydb.close()
	exit()

while True:
	PrintMenu()
