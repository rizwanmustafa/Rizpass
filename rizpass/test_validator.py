import unittest
from .validator import ensure_type, validate_config


class TestValidator(unittest.TestCase):
    def test_ensure_type(self):
        self.assertRaises(TypeError, ensure_type, "string", int, "value", "int")
        self.assertRaises(TypeError, ensure_type, "string", float, "value", "float")
        self.assertRaises(TypeError, ensure_type, "string", list, "value", "list")
        self.assertRaises(TypeError, ensure_type, ["string"], int, "value", "int")
        self.assertRaises(TypeError, ensure_type, 15334, float, "value", "float")
        self.assertEqual(ensure_type("string", str, "value", "str"), None)

    def test_validate_config(self):
        test_config = {"db_type": "sadf", "db_host": "localhost", "db_user": "rizpass", "db_name": "rizpass"}
        validation_result = validate_config(test_config)
        self.assertEqual(validation_result[0], False)
        self.assertEqual(len(validation_result[1]), 1)

        test_config = []
        validation_result = validate_config(test_config)
        self.assertEqual(validation_result[0], False)
        self.assertEqual(len(validation_result[1]), 1)

        test_config = {"db_type": "mongo", "db_host": "localhost", "db_user": "rizpass", "db_name": "rizpass"}
        validation_result = validate_config(test_config)
        self.assertEqual(validation_result[0], True)
        self.assertEqual(len(validation_result[1]), 0)

        test_config = {"db_type": "mongo", "db_host": "localhost", "db_user": "rizpass", "db_name": "rizpass", "db_port": "sadf"}
        validation_result = validate_config(test_config)
        self.assertEqual(validation_result[0], False)
        self.assertEqual(len(validation_result[1]), 1)

        test_config = {"db_type": "mongo", "db_host": "localhost", "db_user": "rizpass", "db_name": "rizpass", "db_port": "sadf", "db_port2": "sadf"}
        validation_result = validate_config(test_config)
        self.assertEqual(validation_result[0], False)
        self.assertEqual(len(validation_result[1]), 2)

        test_config = {"db_type": "mongo", "db_host": "localhost", "db_user": "rizpass", "db_port": 8000}
        validation_result = validate_config(test_config)
        self.assertEqual(validation_result[0], False)
        self.assertEqual(len(validation_result[1]), 1)


if __name__ == "__main__":
    unittest.main()
