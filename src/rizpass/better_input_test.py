import unittest
from unittest.mock import patch

from .better_input import pos_int_input, better_input


class TestValidator(unittest.TestCase):
    @patch("builtins.input")
    def test_better_input(self, mock_input):
        # Test normal input
        mock_input.side_effect = ["1", "1", "1"]
        return_val = better_input("", suppress_output=True)
        self.assertEqual(return_val, "1")

        pass

    @patch("builtins.input")
    def test_pos_int_input_1(self, mock_input):
        # Test valid input on 3rd attempt
        mock_input.side_effect = ["3", "12", "123"]
        return_val = pos_int_input("", suppress_output=True)
        self.assertEqual(return_val, 3)

    @patch("builtins.input")
    def test_pos_int_input_2(self, mock_input):
        # Test invalid input
        mock_input.side_effect = ["-1", "-2", "-3"]
        return_val = pos_int_input("", suppress_output=True)
        self.assertEqual(return_val, None)

    @patch("builtins.input")
    def test_pos_int_input_3(self, mock_input):
        # Test if attempts are working
        mock_input.side_effect = ["-1", "-2", "-3", "4"]
        return_val = pos_int_input("", suppress_output=True, attempts=4)
        self.assertEqual(return_val, 4)

    @patch("builtins.input")
    def test_pos_int_input_4(self, mock_input):
        # Test if optional is working
        mock_input.side_effect = ["-1", "4"]
        return_val = pos_int_input("", suppress_output=True, optional=True)
        self.assertEqual(return_val, None)

    @patch("builtins.input")
    def test_pos_int_input_5(self, mock_input):
        # Test if spaced numbers are working
        mock_input.side_effect = [" 4 "]
        return_val = pos_int_input("", suppress_output=True)
        self.assertEqual(return_val, 4)

    pass


if __name__ == "__main__":
    unittest.main()
