import os
import unittest
from datetime import datetime

from maldump.av_manager import AVManager


class TestExport(unittest.TestCase):

    # Prepare environment
    @classmethod
    def setUpClass(cls):
        os.chdir('test/root')
        cls.avs = [av.export() for av in AVManager.avs]

    def test_list_not_empty(self):
        self.assertIsNotNone(self.avs)

    def test_timestamp(self):
        for av in self.avs:
            for entry in av:
                self.assertIsInstance(entry.timestamp, datetime)

    def test_path_contains_eicar(self):
        for av in self.avs:
            for entry in av:
                self.assertIsNotNone(entry.path)
                self.assertIn('eicar', entry.path)

    def test_file_size(self):
        for av in self.avs:
            for entry in av:
                self.assertEqual(68, entry.size)

    def test_md5_hash(self):
        for av in self.avs:
            for entry in av:
                self.assertEqual(entry.md5, '44d88612fea8a8f36de82e1278abb02f')

    def test_file_is_eicar(self):
        for av in self.avs:
            for entry in av:
                self.assertIsInstance(entry.malfile, bytes)
                self.assertEqual(
                    entry.malfile,
                    br'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'  # noqa: E501
                )


if __name__ == '__main__':
    unittest.main()
