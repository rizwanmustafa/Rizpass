**This project is still under construction**

# Table of Contents
- [Motivation](#motivation)
- [Requirements](#requirements)
- [Installation](#installation)
  * [Installation through PyPi (Recommended)](#installation-through-pypi-recommended)
  * [Installation through Github](#installation-through-github)
  * [But I really really need a binary](#but-i-really-really-need-a-binary)
- [Configuration](#configuration)
  * [Configuration File](#configuration-file)
      - [Sample Configuration File](#sample-configuration-file)

# Motivation

The motivation behind this project was to create a password manager that could get up and running without much setup while still providing features to the enduser.
This is in fact the sole reason behind the file mode which allows you to safely store and retrieve your credentials using a json file.

# Requirements
- Python3 
- Mariadb / MySQL / MongoDB (Optional)

# Installation
If you want to install Rizpass for personal use, you can either install it as a pip package or use the source code / binary provided with the latest release


## Installation through PyPi (Recommended)
```bash
pip install rizpass
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
