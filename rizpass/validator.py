from typing import Union, get_args, get_origin, Tuple, List


def ensure_type(value: any, expected_type: type, valueName: str, typeName: str):
    if get_origin(expected_type) is Union:
        for t in get_args(expected_type):
            if isinstance(value, t):
                return
        raise TypeError(f"{valueName} must be of type {typeName}")

    if not isinstance(value, expected_type):
        raise TypeError(f"Parameter '{valueName}' must be of type '{typeName}'".format(expected_type))


def validate_config(config_obj: any) -> Tuple[bool, List[str]]:
    if not isinstance(config_obj, dict):
        return False, ["Config must be a dictionary / object"]

    errors: List[str] = []

    accepted_keys = {
        "db_type": {"data_type": str, "data_type_name": "string",  "occurred": False, "optional": False, "allowed": ["mongo", "mysql"]},
        "db_host": {"data_type": str, "data_type_name": "string",  "occurred": False, "optional": False},
        "db_user": {"data_type": str, "data_type_name": "string",  "occurred": False, "optional": False},
        "db_name": {"data_type": str, "data_type_name": "string",  "occurred": False, "optional": False},
        "db_port": {"data_type": int, "data_type_name": "integer",  "occurred": False, "optional": True},
    }

    for key in config_obj.keys():
        if key not in accepted_keys:
            errors.append(f"Unknown field '{key}' in config")
            continue
        else:
            accepted_keys[key]["occurred"] = True

        if not isinstance(config_obj[key], accepted_keys[key]["data_type"]):
            errors.append(f"Field '{key}' must be of type '{accepted_keys[key]['data_type_name']}'")

        if "allowed" in accepted_keys[key] and config_obj[key] not in accepted_keys[key]["allowed"]:
            errors.append(f"Field '{key}' must be one of the following: {', '.join(accepted_keys[key]['allowed'])}")

    for key in accepted_keys.keys():
        if not accepted_keys[key]["occurred"] and not accepted_keys[key]["optional"]:
            errors.append(f"Missing field '{key}' in config")

    return (len(errors) == 0, errors)
