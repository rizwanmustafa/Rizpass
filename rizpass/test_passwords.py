import unittest
import string

from .passwords import decrypt_string, generate_password, generate_salt, get_pass_details, follows_password_requirements, encrypt_string, encrypt_and_encode, decode_and_decrypt


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

    def test_generate_password_1(self):
        """Tests if the password is None if all the options are set to False"""
        gen_password = generate_password(8, False, False, False, False, True)

        self.assertEqual(gen_password, None)

    def test_generate_password_2(self):
        """Tests if the password contains characters only from the group that was enabled"""
        gen_password = generate_password(8, True, False, False, False, True)
        self.assertEqual(len(gen_password), 8)
        if not set(string.ascii_uppercase).issuperset(set(gen_password)):
            self.fail("Password contains non-uppercase character(s)")

        gen_password = generate_password(8, False, True, False, False, True)
        self.assertEqual(len(gen_password), 8)
        if not set(string.ascii_lowercase).issuperset(set(gen_password)):
            self.fail("Password contains non-lowercase character(s)")

        gen_password = generate_password(8, False, False, True, False, True)
        self.assertEqual(len(gen_password), 8)
        if not set(string.digits).issuperset(set(gen_password)):
            self.fail("Password contains non-digit character(s)")

        gen_password = generate_password(8, False, False, False, True, True)
        self.assertEqual(len(gen_password), 8)
        if not set(string.punctuation).issuperset(set(gen_password)):
            self.fail("Password contains non-special character")

    def test_generate_password_3(self):
        """Tests if the password contains characters from the two enabled groups"""
        gen_password = generate_password(8, True, True, False, False, True)
        self.assertEqual(len(gen_password), 8)
        if not set(string.ascii_lowercase + string.ascii_uppercase).issuperset(set(gen_password)):
            self.fail("Password contains character(s) other than uppercase and lowercase")

        gen_password = generate_password(8, False, True, True, False, True)
        self.assertEqual(len(gen_password), 8)
        if not set(string.ascii_lowercase + string.digits).issuperset(set(gen_password)):
            self.fail("Password contains character(s) other than lowercase and digits")

        gen_password = generate_password(8, False, False, True, True, True)
        self.assertEqual(len(gen_password), 8)
        if not set(string.digits + string.punctuation).issuperset(set(gen_password)):
            self.fail("Password contains character(s) other than digits and punctuation")

        gen_password = generate_password(8, True, False, False, True, True)
        self.assertEqual(len(gen_password), 8)
        if not set(string.ascii_uppercase + string.punctuation).issuperset(set(gen_password)):
            self.fail("Password contains character(s) other than uppercase and punctuation")

    def test_generate_password_4(self):
        """Tests length of generated passwords"""
        gen_pass = generate_password(8, True, True, True, True, True)
        self.assertNotEqual(gen_pass, None)
        self.assertEqual(len(gen_pass), 8)

        gen_pass = generate_password(16, True, True, True, True, True)
        self.assertNotEqual(gen_pass, None)
        self.assertEqual(len(gen_pass), 16)

        gen_pass = generate_password(32, True, True, True, True, True)
        self.assertNotEqual(gen_pass, None)
        self.assertEqual(len(gen_pass), 32)

        gen_pass = generate_password(48, True, True, True, True, True)
        self.assertNotEqual(gen_pass, None)
        self.assertEqual(len(gen_pass), 48)

    def test_generate_salt(self):
        """Tests the type and length of the bytes returned by generate_salt"""
        salt = generate_salt(32)
        self.assertEqual(type(salt), bytes)
        self.assertEqual(len(salt), 32)

        salt = generate_salt(64)
        self.assertEqual(type(salt), bytes)
        self.assertEqual(len(salt), 64)

        salt = generate_salt(16)
        self.assertEqual(type(salt), bytes)
        self.assertEqual(len(salt), 16)

    def test_encryption_and_decryption(self):
        """Tests if the encryption and decryption works"""
        master_pass = "123"
        payload = "1234567890"
        salt = generate_salt(16)

        encrypted_password = encrypt_string(master_pass, payload, salt)
        self.assertEqual(type(encrypted_password), bytes)

        decrypted_password = decrypt_string(master_pass, encrypted_password, salt)
        self.assertEqual(decrypted_password, payload)

    def test_encrypt_encode_decrypt_decode(self):
        """Tests if the encrypt_and_encode, decode_and_decrypt works"""
        master_pass = "123"
        payload = "1234567890"
        salt = generate_salt(16)

        encrypted_password = encrypt_and_encode(master_pass, payload, salt)
        self.assertEqual(type(encrypted_password), str)

        decrypted_password = decode_and_decrypt(master_pass, encrypted_password, salt)
        self.assertEqual(type(decrypted_password), str)

        self.assertEqual(payload, decrypted_password)


if __name__ == "__main__":
    unittest.main()
