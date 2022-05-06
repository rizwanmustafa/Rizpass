import unittest
from .validator import ensure_type

class TestValidator(unittest.TestCase):
    def test_validator(self):
        self.assertRaises(TypeError, ensure_type, "string", int, "value", "int")
        self.assertRaises(TypeError, ensure_type, "string", float, "value", "float")
        self.assertRaises(TypeError, ensure_type, "string", list, "value", "list")
        self.assertRaises(TypeError, ensure_type, ["string"], int, "value", "int")
        self.assertRaises(TypeError, ensure_type, 15334, float, "value", "float")
        self.assertEqual(ensure_type("string", str, "value", "str"), None)


if __name__ == "__main__":
    unittest.main()