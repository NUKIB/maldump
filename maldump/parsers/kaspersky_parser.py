import sqlite3
from datetime import datetime as dt
from hashlib import md5
from typing import List

from maldump.structures import QuarEntry
from maldump.utils import xor


class KasperskyParser():

    def _normalize_time(self, number):
        year = (number >> 48) & 0xFFFF
        month = (number >> 40) & 0xFF
        days = (number >> 32) & 0xFF
        hours = (number >> 24) & 0xFF
        minutes = (number >> 16) & 0xFF
        seconds = (number >> 8) & 0xFF

        return dt(year, month, days, hours, minutes, seconds)

    def _get_malfile(self, data):
        file = self.location / data
        key = [0xE2, 0x45, 0x48, 0xEC, 0x69, 0x0E, 0x5C, 0xAC]
        with open(file, 'rb') as f:
            return xor(f.read(), key)

    def from_file(self, name, location) -> List[QuarEntry]:
        self.name = name
        self.location = location
        quarfiles = []

        try:
            conn = sqlite3.connect(
                self.location.joinpath('quarantine.db').resolve()
            )
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM 'objects'")
            rows = cursor.fetchall()
        except Exception as e:
            print('Kaspersky DB Error: ' + str(e))

        for row in rows:
            malfile = self._get_malfile(row[0])
            q = QuarEntry()
            q.timestamp = self._normalize_time(row[6])
            q.threat = row[3]
            q.path = row[1] + row[2]
            q.size = row[7]
            q.md5 = md5(malfile).digest().hex()
            q.malfile = malfile
            quarfiles.append(q)

        conn.close()

        return quarfiles
