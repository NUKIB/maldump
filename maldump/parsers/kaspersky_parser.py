from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import TYPE_CHECKING

from maldump.structures import Parser, QuarEntry
from maldump.utils import DatetimeConverter as DTC
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

    def parse_from_log(self, _=None) -> dict[str, QuarEntry]:
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

        return quarfiles

    def parse_from_fs(
        self, data: dict[str, QuarEntry] | None = None
    ) -> dict[str, QuarEntry]:
        quarfiles = {}

        for entry in self.location.glob("{*}"):
            if not entry.is_file():
                continue

            filename = entry.name

            if filename in data:
                continue

            malfile = self._get_malfile(filename)

            entry_stat = entry.stat()
            timestamp = DTC.get_dt_from_stat(entry_stat)
            size = entry_stat.st_size

            q = QuarEntry()
            q.path = str(entry)
            q.timestamp = timestamp
            q.size = size
            q.threat = "Unknown-no-metadata"
            q.malfile = malfile
            quarfiles[filename] = q

        return quarfiles
