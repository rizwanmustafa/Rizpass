def ensure_type(value: any, expected_type: type, valueName: str, typeName: str):
    if not isinstance(value, expected_type):
        raise TypeError(f"Parameter '{valueName}' must be of type '{typeName}'".format(expected_type))
