def ensure_type(expected_type: type, value: object, valueName: str, typeName: str) -> bool:
    if not isinstance(value, expected_type):
        raise TypeError(f"Parameter '{valueName}' must be of type '{typeName}'".format(expected_type))
