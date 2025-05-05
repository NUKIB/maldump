import os
import unittest
from datetime import datetime

from maldump.av_manager import AVManager


class TestExport(unittest.TestCase):
    # Prepare environment
    @classmethod
    def setUpClass(cls) -> None:
        os.chdir("test/root")
        cls.avs = [av.export() for av in AVManager.avs]

    def test_list_not_empty(self) -> None:
        self.assertIsNotNone(self.avs)

    def test_timestamp(self) -> None:
        for av in self.avs:
            for entry in av:
                with self.subTest(i=(entry.av.name, entry.sha1)):
                    self.assertIsInstance(entry.timestamp, datetime)

    def test_path_contains_eicar(self) -> None:
        for av in self.avs:
            for entry in av:
                with self.subTest(i=(entry.av.name, entry.sha1)):
                    self.assertIsNotNone(entry.path)
                    self.assertIn("eicar", entry.path)

    def test_file_size(self) -> None:
        for av in self.avs:
            for entry in av:
                with self.subTest(i=(entry.av.name, entry.sha1)):
                    self.assertEqual(entry.size, 68)

    def test_md5_hash(self) -> None:
        for av in self.avs:
            for entry in av:
                with self.subTest(i=(entry.av.name, entry.sha1)):
                    self.assertEqual(entry.md5, "44d88612fea8a8f36de82e1278abb02f")

    def test_sha1_hash(self) -> None:
        for av in self.avs:
            for entry in av:
                with self.subTest(i=(entry.av.name, entry.sha1)):
                    self.assertEqual(
                        entry.sha1, "3395856ce81f2b7382dee72602f798b642f14140"
                    )

    def test_sha256_hash(self) -> None:
        for av in self.avs:
            for entry in av:
                with self.subTest(i=(entry.av.name, entry.sha1)):
                    self.assertEqual(
                        entry.sha256,
                        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                    )

    def test_file_is_eicar(self) -> None:
        for av in self.avs:
            for entry in av:
                with self.subTest(i=(entry.av.name, entry.sha1)):
                    self.assertIsInstance(entry.malfile, bytes)
                    self.assertEqual(
                        entry.malfile,
                        rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                    )


if __name__ == "__main__":
    unittest.main()
