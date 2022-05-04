**This project is still under construction**
# Table of Contents
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
  * [Configuration File](#configuration-file)
      - [Sample Configuration File](#sample-configuration-file)

# Requirements
- Python3 
- Mariadb / MySQL / MongoDB (Optional)

# Installation

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
