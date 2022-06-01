from typing import Union, get_args, get_origin


def ensure_type(value: any, expected_type: type, valueName: str, typeName: str):
    if get_origin(expected_type) is Union:
        for t in get_args(expected_type):
            if isinstance(value, t):
                return
        raise TypeError(f"{valueName} must be of type {typeName}")

    if not isinstance(value, expected_type):
        raise TypeError(f"Parameter '{valueName}' must be of type '{typeName}'".format(expected_type))
