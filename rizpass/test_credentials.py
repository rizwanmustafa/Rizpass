import unittest
from unittest.mock import patch
import base64

from .credentials import Credential, RawCredential
from .passwords import encrypt_and_encode, decode_and_decrypt, generate_salt

copied = False


class TestRawCredential(unittest.TestCase):
    def test_init(self):
        raw_cred = RawCredential(1, "title", "username", "email", "password", "salt")

        self.assertEqual(raw_cred.id, 1)
        self.assertEqual(raw_cred.title, "title")
        self.assertEqual(raw_cred.username, "username")
        self.assertEqual(raw_cred.email, "email")
        self.assertEqual(raw_cred.password, "password")
        self.assertEqual(raw_cred.salt, "salt")

    def test_get_cred(self):
        salt = generate_salt(16)

        raw_cred = RawCredential(
            1,
            encrypt_and_encode("123", "title", salt),
            encrypt_and_encode("123", "username", salt),
            encrypt_and_encode("123", "email", salt),
            encrypt_and_encode("123", "password", salt),
            base64.b64encode(salt).decode("ascii")
        )

        cred = raw_cred.get_credential("123")

        self.assertEqual(cred.id, 1)
        self.assertEqual(cred.title, "title")
        self.assertEqual(cred.username, "username")
        self.assertEqual(cred.email, "email")
        self.assertEqual(cred.password, "password")

    def test_str(self):
        raw_cred = RawCredential(1, "check_title", "check_username", "check_email", "check_password", "check_salt")
        str_cred = str(raw_cred)

        self.assertEqual("check_title" in str_cred, True)
        self.assertEqual("check_username" in str_cred, True)
        self.assertEqual("check_email" in str_cred, True)
        self.assertEqual("check_password" in str_cred, True)
        self.assertEqual("check_salt" in str_cred, True)


class TestCredentail(unittest.TestCase):
    def test_init(self):
        cred = Credential(1, "title", "username", "email", "password")

        self.assertEqual(cred.id, 1)
        self.assertEqual(cred.title, "title")
        self.assertEqual(cred.username, "username")
        self.assertEqual(cred.email, "email")
        self.assertEqual(cred.password, "password")

    def test_get_raw_cred(self):
        cred = Credential(1, "check_title", "check_username", "check_email", "check_password")
        salt = generate_salt(16)
        raw_cred = cred.get_raw_credential("123", salt)

        self.assertEqual(raw_cred.id, 1)
        self.assertEqual(decode_and_decrypt("123", raw_cred.title, salt), "check_title")
        self.assertEqual(decode_and_decrypt("123", raw_cred.username, salt), "check_username")
        self.assertEqual(decode_and_decrypt("123", raw_cred.email, salt), "check_email")
        self.assertEqual(decode_and_decrypt("123", raw_cred.password, salt), "check_password")
        self.assertEqual(raw_cred.salt, base64.b64encode(salt).decode("ascii"))

    def test_str(self):
        cred = Credential(1, "check_title", "check_username", "check_email", "check_password")
        str_cred = str(cred)

        self.assertEqual("check_title" in str_cred, True)
        self.assertEqual("check_username" in str_cred, True)
        self.assertEqual("check_email" in str_cred, True)
        self.assertEqual("check_password" in str_cred, True)


    def copy_pass(phrase: str):
        global copied
        copied = True

    @patch("pyperclip.copy", new=copy_pass)
    def test_copy_pass(self):
        global copied

        cred = Credential(1, "check_title", "check_username", "check_email", "check_password")
        copied = False
        cred.copy_pass(True)
        self.assertEqual(copied, True)
