def HandleParameterException(name: str, value , type: type, typeName : str):
	if not isinstance(value, type):
		raise TypeError("Parameter '{0}' must be of type '{1}'".format(name, typeName))
	
	if not value:
		raise ValueError("Invalid value provided for parameter '{0}'".format(name))