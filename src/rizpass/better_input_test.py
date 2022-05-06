import unittest
from unittest.mock import patch
from .better_input import pos_int_input, better_input


class TestValidator(unittest.TestCase):
    @patch("builtins.input")
    def test_pos_int_input(self, mock_input):
        # Test valid input on 3rd attempt
        mock_input.side_effect = ["3"]
        return_val = pos_int_input("Enter a positive integer:")
        self.assertEqual(return_val, 3)

        # Test invalid input
        mock_input.side_effect = ["-1", "-2", "-3"]
        return_val = pos_int_input("Enter a positive integer:")
        self.assertEqual(return_val, None)

        # Test if attempts are working
        mock_input.side_effect = ["-1", "-2", "-3", "4"]
        return_val = pos_int_input("Enter a positive integer:", attempts=4)
        self.assertEqual(return_val, 4)

        # Test if optional is working
        mock_input.side_effect = ["-1", "4"]
        return_val = pos_int_input("Enter a positive integer:", optional=True)
        self.assertEqual(return_val, None)

        # Test if spaced numbers are working
        mock_input.side_effect = [" 4 "]
        return_val = pos_int_input("Enter a positive integer:")
        self.assertEqual(return_val, 4)

    pass


if __name__ == "__main__":
    unittest.main()
