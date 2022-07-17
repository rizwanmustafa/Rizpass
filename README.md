**This project is still under construction**

# Table of Contents
- [Motivation](#motivation)
- [Requirements](#requirements)
- [Installation](#installation)
  * [Installation through PyPi (Recommended)](#installation-through-pypi-recommended)
  * [Installation through Github](#installation-through-github)
  * [But I really really need a binary](#but-i-really-really-need-a-binary)
  * [Running Tests](#running-tests)
- [Configuration](#configuration)
  * [Configuration File](#configuration-file)
      - [Sample Configuration File](#sample-configuration-file)
  * [Overriding configuration at runtime](#overriding-configuration-at-runtime)
- [Usage](#usage)
  * [Execution](#execution)
  * [Menu Items](#menu-items)
      - [Generate a strong password](#generate-a-strong-password)
      - [Generate a password](#generate-a-password)
      - [Add a credential](#add-a-credential)
      - [Retrieve credential using id](#retrieve-credential-using-id)
      - [Copy credential to clipboard](#copy-credential-to-clipboard)
      - [Filter credentials](#filter-credentials)
      - [List all credentials](#list-all-credentials)
      - [Modify credential](#modify-credential)
      - [Remove credential](#remove-credential)
      - [Remove all credentials](#remove-all-credentials)
      - [Change master password](#change-master-password)
      - [Export credentials to a JSON file](#export-credentials-to-a-json-file)
      - [Import credentials from a JSON file](#import-credentials-from-a-json-file)
      - [List all raw credentials](#list-all-raw-credentials)
      - [Password checkup](#password-checkup)
  * [File Mode](#file-mode)
  * [Actions](#actions)
  * [Other](#other)

# Motivation

The motivation behind this project was to create a password manager that could get up and running without much setup while still providing features to the enduser.
This is in fact the sole reason behind the file mode which allows you to safely store and retrieve your credentials using a json file.

# Requirements
- Python3 
- Mariadb / MySQL / MongoDB (Optional)

# Installation
If you want to install Rizpass for personal use, you can either install it as a pip package or use the source code / binary provided with the latest release


## Installation through PyPi (Recommended)
The following command will upgrade an existing installation of Rizpass if it is already installed else it will install Rizpass
```bash
pip install --upgrade rizpass
```

## Installation through Github

1. Clone this repository
```bash
git clone https://github.com/rizwanmustafa/Rizpass.git
cd Rizpass
```


2. Create a new virtual environment in a folder called 'venv' for this project (This will prevent your binary size and compilation time from being too long).
```bash
python3 -m venv venv
```

3. Activate the virtual environment:
```bash
source venv/bin/activate
```

4. Install the package
```bash
pip install .
```

5. Start Rizpass
```bash
python3 -m rizpass
```
Note: You can also start rizpass by executing `rizpass` in the terminal directly however this may require modification to the `$PATH` variable


Bonus - If you want to do it all in one step:
```bash
git clone https://github.com/rizwanmustafa/Rizpass.git
cd Rizpass
python3 -m venv venv
source venv/bin/activate
pip install .
python3 -m rizpass
```

## But I really really need a binary
So you want to use Rizpass on the go. 
Since python doesn't have an official compiler we are going to rely on one of it's module called `PyInstaller`.

1. Follow the steps in the [Installation through Github](#installation-through-github)

2. Install `PyInstaller`:
```bash
pip install PyInstaller
```

3. In the same virtual environment that we created, run the following command while in the root directory of the package:
```
python3 -m PyInstaller --onefile rizpass.py
```

4. Upon completion, this will create a binary file for your OS which will be located in  `dist/`

Congratulations, you now have a huge sized binary

## Running tests
It is recommended that you run tests after installation to ensure the best experience. You can run all unit tests through the following command:
```bash
python3 -m rizpass.tests
```


# Configuration

Configuring Rizpass is as simple as running the following command and answering the questions asked

```bash
python3 -m rizpass --setup
```

## Configuration File
Rizpass uses a json object for storing its configuration. The setup command creates a configuration file at `~/.rizpass.json`  
Here is a list of the fields contained in the configuration file and their description:
```
db_type (string, Required) : Name of the database. 'mysql' for MySQL or MariaDB and 'mongo' for MongoDB.
db_host (string, Required) : Address at which the database is hosted e.g 'localhost'
db_name (string, Required) : Name of the database created specifically for Rizpass to store your credentials in.
db_user (string, Required) : Name of the database user created specifically for Rizpass (Should have read and write permissions on the database).
db_port (integer, Optional): Port number for communication with the database. Defaults to 3306 for 'mysql' and 27017 for 'mongo'.
```

#### Sample Configuration File

```json
{"db_type": "mongo", "db_host": "localhost", "db_user": "passMan", "db_name": "rizpass", "db_port": 7000}
```

## Overriding configuration at runtime
You can override the configurations stored in a file on runtime using the following cli options:
```
--db-host <host>        Database host
--db-type <type>        Database type (mongo, mysql)
--db-user <user>        Database user
--db-name <name>        Database name
--db-port <port>        Database port
```

You can also use all these options together to use Rizpass without a configuration file.

# Usage

## Execution

You can execute Rizpass through the following commmand:
```bash
python3 -m rizpass
```

## Menu Items

#### Generate a strong password
This menu item allows one to generate a strong password that contains all kinds of characters (uppercase, lowercase, special, digit) to enhance security. The generated passwords stand strong against dictionary attacks as they are truly random and not easy to guess. In this option the minimum length of a generated password can be 16 characters

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass generate-strong
```

#### Generate a password
This menu item allows one to generate a password with the traits of their choice. The user can choose the length and the type of characters they want to include in the generated password. This option is less secure than the option mentioned above but allows for greater customizability.

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass generate
```

#### Add a credential
This menu items allows one to store a new credential. Users can store the credential data in the following fields: 'title', 'username', 'email' and 'password'. Rizpass automatically adds a unique 'id' field to the credential for use in other menu items

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass add
```

#### Retrieve credential using id
This menu item takes the 'id' of a credential as an input from the user and prints the credential if it exists.

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass retrieve
```

#### Copy credential to clipboard
This menu item takes the 'id' of a credential as an input from the user and copies the password to the clipboard if it exists. For this menu item to work, pyperclip must be able to find a copy mechanism for your system.

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass copy
```

#### Filter credentials
This menu item allows the users to provide 'filters' for the following fields: 'title', 'username', 'email'. A 'filter' for a field is just character(s) that each credential's matching field must contain. If no 'filter' is provided for a particular field, all values for that field will be considered valid. If no 'filters' are provided at all, all stored credentials will be returned.

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass filter
```

#### List all credentials
This menu item prints all the stored credentials to the screen.

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass list-all
```

#### Modify credential
This menu item takes the credential 'id' as an input. It then takes in replacement values for each field for that credential. If a replacement value for a field is empty, the field value will not be modified.

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass modify
```

#### Remove credential
This menu item takes the credential 'id' as an input and removes the stored credential if it exists.

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass remove
```

#### Remove all credentials
This menu item first confirms if you are sure about what you intend to do. It then prompts you to re enter the master password, if the master password is incorrect, it exits, else it removes all stored credentials. Remember this is a permanent change.

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass remove-all
```

#### Change master password
This menu item changes the master password you use to log in to Rizpass. It first confirms your intentions and then prompts you for the current master password. If incorrect, it exits, else it continues with the process. It then asks you for the new master password. If you are using the database option, it will ask for the root credentials to change the password of the database user. It then re-encrypts the stored credentials using the new master password. Remember this is a permanent change.

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass change-master-pass
```

#### Export credentials to a JSON file
This menu item allows you to export your encrypted credentials to a JSON file to allow for portability. It will ask you for the file path and the master password for this file. You can choose a separate master password for the exported credentials but if you do not provide a separate master password, it will encrypt the credentials with your current master password. You can then use this file with the file mode of Rizpass to access your credentials on the go.

We recommend you use this feature to backup your credentials regularly. It is also recommended to store this file in a safe place.

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass export
```

#### Import credentials from a JSON file
This menu item allows you to import your encrypted credentials from a JSON file that was exported using the export menu item of Rizpass. Rizpass will prompt you to provide the path of the file and the master password for this file when you try to import it. It will then try to re-encrypt all credentials in the file and store them.

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass import
```

#### List all raw credentials
This menu item is similar to the "List all credentials" menu item but there is one key difference. It prints the encrypted version of the stored credentials on the screen rather than the usual decrypted version of the credentials.

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass list-raw
```

#### Password checkup
This menu item goes over your stored credentials and scans for passwords that are either weak or duplicate. For detecting weak passwords, it jsut checks if a password follows the guidlines that this item prints before beginning the checkup. It is completely possible for this item to miss weak passwords like "p@$$w0rdp@$$w0rd123". Hence this is why it is recommended to use passwords generated from the "Genearate a strong password" menu item.

You can access this feature through the commandline by the following command:
```bash
python3 -m rizpass pass-checkup
```

## File Mode

A major reason behind the creation of Rizpass was to have ease of use and to prevent confusion among the users. Rizpass supports file mode whereby all operations are performed on a JSON file instead of a database. This can help those who don't want to go through the process of setting up a database and those who want portability

You can access the file mode using the following command:
```bash
python3 -m rizpass --file <file_name>
```

## Actions
Since Rizpass is a CLI tool, it is designed to be as cli-friendly as possible. Hence, if you don't like the extensive menu and know exactly what you want to do, you can use actions. For example if you want to add a credential, you can do so through the terminal:
```
python3 -m rizpass add
```
Plus you can use this feature to perform multiple tasks in one go without touching the menu:
```
python3 -m rizpass add list-all generate-strong pass-checkup
```
However with great power comes great responsibility.

## Other

You can print the help menu through the following command:
```bash
python3 -m rizpass --help
```

You can print the version of Rizpass you are using through the following command:
```bash
python3 -m rizpass --version
```

You can have verbose output through the following command:
```bash
python3 -m rizpass --verbose
```
