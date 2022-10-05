#!/usr/bin/env python3
import os
import json
from getpass import getpass
from sys import exit, argv, stderr
from typing import Callable, List, Dict, NoReturn, Tuple, Union
import signal

from .output import print_blue, print_colored, print_red, set_colored_output, set_verbose_output
from . import user_functions

CONFIG_FILE_PATH = os.path.expanduser("~/.rizpass.json")

master_pass:  str = None
creds_file_path: str = None
creds_manager = None

config: Dict[str, str] = {
    "file_path": None,
    "db_type": None,
    "db_host": None,
    "db_user": None,
    "db_name": None,
    "db_port": None
}


def perform_tasks() -> None:
    from .better_input import better_input
    max_limit = len(menu_items.keys())

    user_choice = better_input(
        "Choice: ",
        validator=lambda x:  True if x.isnumeric() and int(x) <= max_limit and int(x) > 0 else f"Choice must be <= {max_limit} and >= 1"
    )

    if user_choice == None:
        return

    user_choice = int(user_choice)

    clear_console()

    menu_items[user_choice][1](master_pass, creds_manager)

    print()
    input("Press enter to continue...")


def load_db_config(
    db_host: Union[str, None] = None,
    db_type: Union[str, None] = None,
    db_user: Union[str, None] = None,
    db_name: Union[str, None] = None,
    db_port: Union[int, None] = None
) -> bool:
    from .validator import validate_config, ensure_type
    from .output import print_yellow

    ensure_type(db_host, Union[str, None], "db_host", "string | None")
    ensure_type(db_type, Union[str, None], "db_type", "string | None")
    ensure_type(db_user, Union[str, None], "db_user", "string | None")
    ensure_type(db_name, Union[str, None], "db_name", "string | None")
    ensure_type(db_port, Union[int, None], "db_port", "int | None")

    # Deal with parameter overrides
    required_overrides_present = db_host != None and db_type != None and db_user != None and db_name != None
    # overrides = []
    # if db_host:
    #     overrides.append("db_host")
    # if db_type:
    #     overrides.append("db_type")
    # if db_user:
    #     overrides.append("db_user")
    # if db_name:
    #     overrides.append("db_name")
    # if db_port:
    #     overrides.append("db_port")

    global config
    user_settings = {}

    if required_overrides_present and db_port == None:
        print_yellow("Using default value for db_port depending on database")

    if not required_overrides_present:
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
            print_colored(f"Please fix the configuration file located at {{yellow}}{CONFIG_FILE_PATH}{{reset}}", file=stderr)
            exit(1)

        config_file.seek(0, 0)
        try:
            user_settings = json.load(config_file)
        except Exception as e:
            print_red("Could not load configuration file due to the following error:", file=stderr)
            print_red(e, file=stderr)
            return False

        config_file.close()

        if type(user_settings) != dict:
            print_red("Invalid configuration file!", file=stderr)

    db_host = db_host or user_settings.get("db_host", None)
    db_user = db_user or user_settings.get("db_user", None)
    db_name = db_name or user_settings.get("db_name", None)
    db_type = db_type or user_settings.get("db_type", None)
    db_port = db_port or user_settings.get("db_port", None) or (3306 if db_type == "mysql" else 27017)

    config_validation = validate_config({
        "db_host":  db_host,
        "db_user":  db_user,
        "db_name":  db_name,
        "db_type":  db_type,
        "db_port":  db_port,
    })

    if not config_validation[0]:
        print_red("Configuration is invalid!", file=stderr)
        for errors in config_validation[1]:
            print(f"{errors}", file=stderr)
        print()
        print_colored(f"Reminder: Configuration file is located at {{yellow}}{CONFIG_FILE_PATH}{{reset}}", file=stderr)
        exit(1)

    config["db_host"] = db_host
    config["db_user"] = db_user
    config["db_name"] = db_name
    config["db_type"] = db_type
    config["db_port"] = db_port

    return True


def clear_console() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def signal_handler(signum, frame):
    signal.signal(signum, signal.SIG_IGN)
    print("\n\nExiting gracefully...")
    exit_app(130)


signal.signal(signal.SIGINT, signal_handler)


def exit_app(exit_code=0) -> NoReturn:
    creds_manager.close() if creds_manager else None
    exit(exit_code)


def process_args(args: List[str]) -> Dict[str, str]:
    """Processes command line arguments and returns a dictionary of the arguments with their values if possible."""
    from .misc import get_list_item_safely, print_help
    from .validator import ensure_type
    ensure_type(args, list, "args", "list")

    ignore_args = {0}

    args_dict = dict({
        "config_file_path": None,
        "db_host": None,
        "db_type": None,
        "db_user": None,
        "db_name": None,
        "db_port": None,
        "print_version": False,
        "print_help": False,
        "init_setup": False,
        "file_mode": False,
        "file_path": None,
        "color_mode": True,
        "actions": [],
        "clear_console": False,
        "no_clear_console": False,
        "verbose": False,
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
                print_help(True)
                exit_app(129)
            ignore_args.add(index + 1)

        elif arg == "--config-file":
            args_dict["config_file_path"] = get_list_item_safely(args, index + 1)
            if args_dict["config_file_path"] == None:
                print_red("Invalid config file path!", file=stderr)
                exit_app(129)
            ignore_args.add(index + 1)

        elif arg == "--setup" or arg == "-s":
            args_dict["init_setup"] = True
        elif arg == "--db-host":
            args_dict["db_host"] = get_list_item_safely(args, index + 1)
            if args_dict["db_host"] == None:
                print_red("Invalid database host!", file=stderr)
                exit_app(129)
            ignore_args.add(index + 1)

        elif arg == "--db-type":
            args_dict["db_type"] = get_list_item_safely(args, index + 1)
            if args_dict["db_type"] == None or args_dict["db_type"] not in ["mysql", "mongo"]:
                print_red("Invalid database type!", file=stderr)
                exit_app(129)
            ignore_args.add(index + 1)

        elif arg == "--db-user":
            args_dict["db_user"] = get_list_item_safely(args, index + 1)
            if args_dict["db_user"] == None:
                print_red("Invalid database user!", file=stderr)
                exit_app(129)
            ignore_args.add(index + 1)

        elif arg == "--db-name":
            args_dict["db_name"] = get_list_item_safely(args, index + 1)
            if args_dict["db_name"] == None:
                print_red("Invalid database name!", file=stderr)
                exit_app(129)
            ignore_args.add(index + 1)

        elif arg == "--db-port":
            args_dict["db_port"] = get_list_item_safely(args, index + 1)
            if args_dict["db_port"] == None or not args_dict["db_port"].isdigit():
                print_red("Invalid database port!", file=stderr)
                exit_app(129)
            args_dict["db_port"] = int(args_dict["db_port"])
            ignore_args.add(index + 1)

        elif arg == "--no-color":
            args_dict["color_mode"] = False
        elif arg == "--clear":
            args_dict["clear_console"] = True
        elif arg == "--no-clear":
            args_dict["no_clear_console"] = True
        elif arg == "--verbose":
            args_dict["verbose"] = True

        elif arg == "generate-strong":
            args_dict["actions"].append(1)
        elif arg == "generate":
            args_dict["actions"].append(2)
        elif arg == "add":
            args_dict["actions"].append(3)
        elif arg == "retrieve":
            args_dict["actions"].append(4)
        elif arg == "copy":
            args_dict["actions"].append(5)
        elif arg == "filter":
            args_dict["actions"].append(6)
        elif arg == "list-all":
            args_dict["actions"].append(7)
        elif arg == "modify":
            args_dict["actions"].append(8)
        elif arg == "remove":
            args_dict["actions"].append(9)
        elif arg == "remove-all":
            args_dict["actions"].append(10)
        elif arg == "change-master-pass":
            args_dict["actions"].append(11)
        elif arg == "export":
            args_dict["actions"].append(12)
        elif arg == "import":
            args_dict["actions"].append(13)
        elif arg == "list-raw":
            args_dict["actions"].append(14)
        elif arg == "pass-checkup":
            args_dict["actions"].append(15)
        else:
            print_red(f"Invalid argument: {arg}", file=stderr)
            print_help(True)
            exit_app(129)

    return args_dict


def handle_processed_args(options: Dict[str, str]) -> None:
    """Load config from arguments"""
    from .misc import print_help, print_license
    set_colored_output(options.get("color_mode"))

    if options.get("print_help"):
        print_help()
        exit_app(0)
    if options.get("print_version"):
        print_license()
        exit_app(0)

    if options.get("init_setup"):
        from .setup_rizpass import setup_password_manager
        setup_password_manager()
        exit_app(0)

    def empty():
        pass

    global config, clear_console

    if options.get("no_clear_console"):
        clear_console = empty

    if options.get("config_file_path"):
        global CONFIG_FILE_PATH
        CONFIG_FILE_PATH = os.path.expanduser(options.get("config_file_path"))

    if options.get("verbose"):
        set_verbose_output(True)

    if options.get("file_mode"):
        config["file_path"] = options.get("file_path")
    else:
        exit(1) if not load_db_config(
            options.get("db_host"),
            options.get("db_type"),
            options.get("db_user"),
            options.get("db_name"),
            options.get("db_port"),
        ) else None

    # Print license
    print_license()
    print()

    # Login
    global master_pass, creds_manager

    options.get("actions") and print_blue("Running in action mode...\n")
    master_pass = getpass("Master Password: ")

    setup_creds_manager()

    user_functions.init(exit_app, config)

    action_len = len(options.get("actions", []))

    if options.get("actions"):
        for index, action in enumerate(options.get("actions")):
            print_blue(f"\nBegin action no: {index + 1} Remaining actions: {action_len - index - 1}\n")
            menu_items[action][1](master_pass, creds_manager)

        if options.get("clear_console"):
            clear_console()
        exit_app()


def setup_creds_manager():
    global creds_manager

    if config.get("file_path"):
        from .file_manager import FileManager
        creds_manager = FileManager(config.get("file_path"))
        return

    from .database_manager import DbConfig
    db_config = DbConfig(
        config.get("db_host"),
        config.get("db_user"),
        master_pass,
        config.get("db_name"),
        config.get("db_port")
    )

    if config.get("db_type") == "mysql":
        from .database_manager import MysqlManager
        creds_manager = MysqlManager(db_config)
    else:
        from .database_manager import MongoManager
        creds_manager = MongoManager(db_config)


menu_items: Dict[str, Tuple[str, Callable]] = {
    1: ("Generate a strong password", user_functions.generate_strong_password),
    2: ("Generate a password", user_functions.generate_password),
    3: ("Add a credential", user_functions.add_credential),
    4: ("Retrieve credential using id", user_functions.get_credential),
    5: ("Copy credential to clipboard", user_functions.copy_password),
    6: ("Filter credentials", user_functions.filter_credentials),
    7: ("List all credentials", user_functions.get_all_credentials),
    8: ("Modify credential", user_functions.modify_credential),
    9: ("Remove credential", user_functions.remove_credential),
    10: ("Remove all credentials", user_functions.remove_all_credentials),
    11: ("Change master password", user_functions.change_masterpass),
    12: ("Export credentials to a JSON file", user_functions.export_credentials),
    13: ("Import credentials from a JSON file", user_functions.import_credentials),
    14: ("List all raw credentials", user_functions.get_all_raw_credentials),
    15: ("Password checkup", user_functions.password_checkup),
    16: ("Exit", lambda x, y: exit_app()),


}


def print_menu():
    from .misc import VERSION_NUMBER
    clear_console()
    print_colored("{blue}" + "-------------------------------" + "{reset}")
    print_colored("{blue}" + f"Rizpass {VERSION_NUMBER}" + "{reset}")
    print_colored("{blue}" + "Mode: " + "{reset}" + '{yellow}' + creds_manager.get_mode() + "{reset}")
    print()

    for key in menu_items:
        print_colored("{blue}" + str(key).ljust(2) + "{reset}  " + menu_items[key][0])

    print_colored("{blue}" + "-------------------------------" + '{reset}')


def init_interactive():
    processed_args = process_args(argv)
    handle_processed_args(processed_args)

    while True:
        print_menu()
        perform_tasks()


if __name__ == "__main__":
    init_interactive()
