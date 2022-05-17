import unittest
import tempfile
import os
from time import time

from .file_manager import FileManager

TEMP_FILE_PATH = f"{tempfile.gettempdir()}/rizpass_test_file_manager_{int(time())}.json"


class TestFileManager(unittest.TestCase):
    def read_from_file(self):
        file = open(TEMP_FILE_PATH, "r")
        contents = file.read()
        file.close()
        return contents

    def test_add_credential(self):
        manager = FileManager(TEMP_FILE_PATH)
        manager.add_credential("Test Title", "Test Username", "Test Email", "Test Password", "Test Salt")

        self.assertEqual(len(manager.credentials), 1)
        self.assertEqual(manager.credentials[0].title, "Test Title")
        self.assertEqual(manager.credentials[0].username, "Test Username")
        self.assertEqual(manager.credentials[0].email, "Test Email")
        self.assertEqual(manager.credentials[0].password, "Test Password")
        self.assertEqual(manager.credentials[0].salt, "Test Salt")

        manager.close()
        self.assertEqual(
            self.read_from_file(),
            '[{"id": 1, "title": "Test Title", "username": "Test Username", "email": "Test Email", "password": "Test Password", "salt": "Test Salt"}]'
        )
        os.remove(TEMP_FILE_PATH)

    def test_get_all_creds(self):
        manager = FileManager(TEMP_FILE_PATH)
        manager.add_credential("Test Title", "Test Username", "Test Email", "Test Password", "Test Salt")
        manager.add_credential("Test Title 2", "Test Username 2", "Test Email 2", "Test Password 2", "Test Salt 2")

        all_creds = manager.get_all_credentials()

        self.assertEqual(len(all_creds), 2)

        self.assertEqual(all_creds[0].title, "Test Title")
        self.assertEqual(all_creds[0].username, "Test Username")
        self.assertEqual(all_creds[0].email, "Test Email")
        self.assertEqual(all_creds[0].password, "Test Password")
        self.assertEqual(all_creds[0].salt, "Test Salt")

        self.assertEqual(all_creds[1].title, "Test Title 2")
        self.assertEqual(all_creds[1].username, "Test Username 2")
        self.assertEqual(all_creds[1].email, "Test Email 2")
        self.assertEqual(all_creds[1].password, "Test Password 2")
        self.assertEqual(all_creds[1].salt, "Test Salt 2")

        manager.close()
        self.assertEqual(
            self.read_from_file(),
            '[{"id": 1, "title": "Test Title", "username": "Test Username", "email": "Test Email", "password": "Test Password", "salt": "Test Salt"}, {"id": 2, "title": "Test Title 2", "username": "Test Username 2", "email": "Test Email 2", "password": "Test Password 2", "salt": "Test Salt 2"}]'
        )
        os.remove(TEMP_FILE_PATH)

    def test_get_credential(self):
        manager = FileManager(TEMP_FILE_PATH)
        manager.add_credential("Test Title", "Test Username", "Test Email", "Test Password", "Test Salt")
        manager.add_credential("Test Title 2", "Test Username 2", "Test Email 2", "Test Password 2", "Test Salt 2")

        cred = manager.get_credential(2)

        self.assertEqual(cred.title, "Test Title 2")

        manager.close()
        self.assertEqual(
            self.read_from_file(),
            '[{"id": 1, "title": "Test Title", "username": "Test Username", "email": "Test Email", "password": "Test Password", "salt": "Test Salt"}, {"id": 2, "title": "Test Title 2", "username": "Test Username 2", "email": "Test Email 2", "password": "Test Password 2", "salt": "Test Salt 2"}]'
        )
        os.remove(TEMP_FILE_PATH)

    def test_remove_credential(self):
        manager = FileManager(TEMP_FILE_PATH)
        manager.add_credential("Test Title", "Test Username", "Test Email", "Test Password", "Test Salt")
        manager.remove_credential(1)

        self.assertEqual(len(manager.credentials), 0)

        manager.close()
        self.assertEqual(self.read_from_file(), "[]")
        os.remove(TEMP_FILE_PATH)

    def test_remove_all_credentials(self):
        manager = FileManager(TEMP_FILE_PATH)
        manager.add_credential("Test Title", "Test Username", "Test Email", "Test Password", "Test Salt")
        manager.add_credential("Test Title 2", "Test Username 2", "Test Email 2", "Test Password 2", "Test Salt 2")
        manager.remove_all_credentials()

        self.assertEqual(len(manager.credentials), 0)

        manager.close()
        self.assertEqual(self.read_from_file(), "[]")
        os.remove(TEMP_FILE_PATH)

    def test_modify_credential(self):
        manager = FileManager(TEMP_FILE_PATH)
        manager.add_credential("Test Title", "Test Username", "Test Email", "Test Password", "Test Salt")
        manager.modify_credential(1, "Test Title 2", "Test Username 2", "Test Email 2", "Test Password 2", "Test Salt 2")

        self.assertEqual(len(manager.credentials), 1)
        self.assertEqual(manager.credentials[0].title, "Test Title 2")
        self.assertEqual(manager.credentials[0].username, "Test Username 2")
        self.assertEqual(manager.credentials[0].email, "Test Email 2")
        self.assertEqual(manager.credentials[0].password, "Test Password 2")

        manager.close()
        self.assertEqual(
            self.read_from_file(),
            '[{"id": 1, "title": "Test Title 2", "username": "Test Username 2", "email": "Test Email 2", "password": "Test Password 2", "salt": "Test Salt 2"}]'
        )
        os.remove(TEMP_FILE_PATH)

    # TODO: Find some way of testing this
    # def test_filter_credentials(self):
    #     manager = FileManager(TEMP_FILE_PATH)
    #     manager.add_credential("Test Title", "Test Username", "Test Email", "Test Password", "Test Salt")
    #     manager.add_credential("Test Title 2", "Test Username 2", "Test Email 2", "Test Password 2", "Test Salt 2")
    #     manager.add_credential("Test Title 3", "Test Username 3", "Test Email 3", "Test Password 3", "Test Salt 3")

    #     filtered_creds = manager.filter_credentials("Test Title", "", "", "")

    #     self.assertEqual(len(filtered_creds), 2)

    #     manager.close()
        # os.remove(TEMP_FILE_PATH)


if __name__ == "__main__":
    unittest.main()
