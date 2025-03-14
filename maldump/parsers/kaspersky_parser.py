from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import TYPE_CHECKING

from maldump.structures import QuarEntry, Parser
from maldump.utils import xor

if TYPE_CHECKING:
    from pathlib import Path


class KasperskyParser(Parser):
    def _normalize_time(self, number: int) -> datetime:
        year = (number >> 48) & 0xFFFF
        month = (number >> 40) & 0xFF
        days = (number >> 32) & 0xFF
        hours = (number >> 24) & 0xFF
        minutes = (number >> 16) & 0xFF
        seconds = (number >> 8) & 0xFF

        return datetime(year, month, days, hours, minutes, seconds)

    def _get_malfile(self, data) -> bytes:
        file = self.location / data
        key = [0xE2, 0x45, 0x48, 0xEC, 0x69, 0x0E, 0x5C, 0xAC]
        with open(file, "rb") as f:
            return xor(f.read(), key)

    def from_file(self, name: str, location: Path) -> list[QuarEntry]:
        self.name = name
        self.location = location
        quarfiles = {}

        try:
            conn = sqlite3.connect(self.location.joinpath("quarantine.db").resolve())
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM 'objects'")
            rows = cursor.fetchall()
        except sqlite3.Error as e:
            print("Kaspersky DB Error: " + str(e))

        for row in rows:
            filename = row[0]
            malfile = self._get_malfile(filename)
            q = QuarEntry()
            q.timestamp = self._normalize_time(row[6])
            q.threat = row[3]
            q.path = row[1] + row[2]
            q.size = row[7]
            q.malfile = malfile
            quarfiles[filename] = q

        conn.close()

        for entry in self.location.glob("{*}"):
            filename = entry.name

            if filename in quarfiles:
                continue

            if not entry.is_file():
                continue

            malfile = self._get_malfile(filename)

            entry_stat = entry.stat()

            ctime = entry_stat.st_ctime_ns
            try:
                ctime = entry_stat.st_birthtime_ns
            except AttributeError:
                # logging
                pass
            size = entry_stat.st_size

            q = QuarEntry()
            q.path = str(entry)
            q.timestamp = datetime.fromtimestamp(ctime // 1000000000)
            q.size = size
            q.threat = "Unknown-no-metadata"
            q.malfile = malfile
            quarfiles[filename] = q

        return list(quarfiles.values())
