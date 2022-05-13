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

    def test_follows_password_requirements_1(self):
        """ Tests lowercase parameter """
        password = "password"

        follows_requirements, errors = follows_password_requirements(password, 8, 0, 8, 0, 0)
        self.assertEqual(follows_requirements, True)
        self.assertEqual(errors, [])

        follows_requirements, errors = follows_password_requirements(password, 8, 0, 16, 0, 0)
        self.assertEqual(follows_requirements, False)
        self.assertEqual(len(errors), 1)

    def test_follows_password_requirements_2(self):
        """ Tests uppercase parameter """
        password = "PASSWORD"

        follows_requirements, errors = follows_password_requirements(password, 8, 8, 0, 0, 0)
        self.assertEqual(follows_requirements, True)
        self.assertEqual(errors, [])

        follows_requirements, errors = follows_password_requirements(password, 8, 16, 0, 0, 0)
        self.assertEqual(follows_requirements, False)
        self.assertEqual(len(errors), 1)

    def test_follows_password_requirements_3(self):
        """ Tests digits parameter """
        password = "12345678"

        follows_requirements, errors = follows_password_requirements(password, 8, 0, 0, 8, 0)
        self.assertEqual(follows_requirements, True)
        self.assertEqual(errors, [])

        follows_requirements, errors = follows_password_requirements(password, 8, 0, 0, 16, 0)
        self.assertEqual(follows_requirements, False)
        self.assertEqual(len(errors), 1)

    def test_follows_password_requirements_4(self):
        """ Tests special parameter """
        password = "!@#$%^&*"

        follows_requirements, errors = follows_password_requirements(password, 8, 0, 0, 0, 8)
        self.assertEqual(follows_requirements, True)
        self.assertEqual(errors, [])

        follows_requirements, errors = follows_password_requirements(password, 8, 0, 0, 0, 16)
        self.assertEqual(follows_requirements, False)
        self.assertEqual(len(errors), 1)

    def test_follows_password_requirements_5(self):
        """ Tests all parameters """
        password = "1234567890"
        follows_requirements, errors = follows_password_requirements(password, 12, 3, 3, 3, 3)
        self.assertEqual(follows_requirements, False)
        self.assertEqual(len(errors), 4)

        follows_requirements, errors = follows_password_requirements(password, 8, 0, 0, 0, 0)
        self.assertEqual(follows_requirements, True)
        self.assertEqual(errors, [])

        password = "abcABC123!@?"
        follows_requirements, errors = follows_password_requirements(password, 12, 3, 3, 3, 3)
        self.assertEqual(follows_requirements, True)
        self.assertEqual(errors, [])

        follows_requirements, errors = follows_password_requirements(password, 16, 3, 3, 3, 3)
        self.assertEqual(follows_requirements, False)
        self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
