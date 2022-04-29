def get_config_schema():
    return {
        "db_type": {
            "type": "string",
            "allowed": ["mongo", "mysql"],
            "required": True
        },
        "db_host": {
            "type": "string",
            "required": True
        },
        "db_user": {
            "type": "string",
            "required": True
        },
        "db_name": {
            "type": "string",
            "required": True
        },
        "db_port": {
            "type": "integer",
            "required": False
        }
    }
