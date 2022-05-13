import unittest

from .passwords import get_pass_details, follows_password_requirements


class TestPasswords(unittest.TestCase):
    def test_get_pass_details_1(self):
        password = "password"
        pass_details = get_pass_details(password)
        self.assertEqual(pass_details["length"], 8)
        self.assertEqual(pass_details["uppercase"], 0)
        self.assertEqual(pass_details["lowercase"], 8)
        self.assertEqual(pass_details["digits"], 0)
        self.assertEqual(pass_details["special"], 0)

    def test_get_pass_details_2(self):
        password = "PASSWORD"
        pass_details = get_pass_details(password)
        self.assertEqual(pass_details["length"], 8)
        self.assertEqual(pass_details["uppercase"], 8)
        self.assertEqual(pass_details["lowercase"], 0)
        self.assertEqual(pass_details["digits"], 0)
        self.assertEqual(pass_details["special"], 0)

    def test_get_pass_details_3(self):
        password = "12345678"
        pass_details = get_pass_details(password)
        self.assertEqual(pass_details["length"], 8)
        self.assertEqual(pass_details["uppercase"], 0)
        self.assertEqual(pass_details["lowercase"], 0)
        self.assertEqual(pass_details["digits"], 8)
        self.assertEqual(pass_details["special"], 0)

    def test_get_pass_details_4(self):
        password = "1234567890"
        pass_details = get_pass_details(password)
        self.assertEqual(pass_details["length"], 10)
        self.assertEqual(pass_details["uppercase"], 0)
        self.assertEqual(pass_details["lowercase"], 0)
        self.assertEqual(pass_details["digits"], 10)
        self.assertEqual(pass_details["special"], 0)

    def test_get_pass_details_5(self):
        password = "abcABC123!@?"
        pass_details = get_pass_details(password)
        self.assertEqual(pass_details["length"], 12)
        self.assertEqual(pass_details["uppercase"], 3)
        self.assertEqual(pass_details["lowercase"], 3)
        self.assertEqual(pass_details["digits"], 3)
        self.assertEqual(pass_details["special"], 3)

    # TODO: Write tests for testing follows_password_requirements



if __name__ == "__main__":
    unittest.main()
