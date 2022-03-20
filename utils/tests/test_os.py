import unittest
import subprocess

from utils.os import hash_bytes, read_file_bytes

class TestOS(unittest.TestCase):
    def test_hash_bytes(self):
        """
        Verifies that the internal hashing function gives the same result
        as the sha256sum command-line tool.

        E.g., hashbytes(f.read()) == sha256sum file.exe
        """
        test_file_path = 'README.md'
        cmd_output = subprocess.run(['sha256sum', test_file_path], stdout=subprocess.PIPE)
        expected = cmd_output.stdout.decode('utf-8').split(' ')[0]

        data = read_file_bytes(test_file_path)
        actual = hash_bytes(data)

        self.assertEqual(expected, actual)

if __name__ == '__main__':
    unittest.main()