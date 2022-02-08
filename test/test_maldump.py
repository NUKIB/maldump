import os
import unittest
from datetime import datetime
from hashlib import md5

from maldump.av_manager import AVManager

class TestOutput(unittest.TestCase):

    # Prepare environment
    def setUpClass():
        os.chdir('test/root')

    def test_export(self):
        for av in AVManager.avs:
            for entry in av.export():
                #self.assertIsInstance(entry.timestamp, datetime)
                self.assertIsNotNone(entry.path)
                self.assertIn('eicar', entry.path)
                self.assertEqual(68, entry.size)
                self.assertEqual(entry.md5, '44d88612fea8a8f36de82e1278abb02f')
                self.assertIsInstance(entry.malfile, bytes)
                self.assertEqual
                (
                    entry.malfile,
                    b'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
                )


if __name__ == '__main__':
    unittest.main()
