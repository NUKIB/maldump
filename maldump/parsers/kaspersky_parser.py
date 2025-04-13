from __future__ import annotations

import logging
import sqlite3
from datetime import datetime

from maldump.constants import ThreatMetadata
from maldump.structures import Parser, QuarEntry
from maldump.utils import DatetimeConverter as DTC
from maldump.utils import Parser as parse
from maldump.utils import Reader as read
from maldump.utils import xor


def log_fn(func):
    def wrapper(*args, **kwargs):
        logging.debug(
            "Calling function: %s, arguments: %s, keyword arguments: %s",
            func.__name__,
            tuple(
                (
                    arg
                    if type(arg) not in {bytes, KasperskyParser}
                    else "<" + type(arg).__name__ + ">"
                )
                for arg in args
            ),
            kwargs,
        )
        return func(*args, **kwargs)

    return wrapper


class KasperskyParser(Parser):
    @log_fn
    def _normalize_time(self, number: int) -> datetime:
        year = (number >> 48) & 0xFFFF
        month = (number >> 40) & 0xFF
        days = (number >> 32) & 0xFF
        hours = (number >> 24) & 0xFF
        minutes = (number >> 16) & 0xFF
        seconds = (number >> 8) & 0xFF

        return datetime(year, month, days, hours, minutes, seconds)

    @log_fn
    def _get_malfile(self, data) -> bytes:
        file = self.location / data
        key = bytes([0xE2, 0x45, 0x48, 0xEC, 0x69, 0x0E, 0x5C, 0xAC])

        data = read.contents(file, filetype="malware")
        if data is None:
            return b""

        return xor(data, key)

    def parse_from_log(self, _=None) -> dict[str, QuarEntry]:
        logging.info("Parsing from log in %s", self.name)
        quarfiles = {}

        db_file = self.location.joinpath("quarantine.db").resolve()
        try:
            logging.debug(
                'Trying to open and read from database file, path "%s"', db_file
            )
            conn = sqlite3.connect(db_file)
            logging.debug('Opening cursor to a database connection, path "%s"', db_file)
            cursor = conn.cursor()
            logging.debug(
                'Exectuting a command with a database connection, path "%s"', db_file
            )
            cursor.execute("SELECT * FROM 'objects'")
            rows = cursor.fetchall()
        except sqlite3.Error as e:
            logging.exception(
                'Cannot open nor read from a database file, path "%s"',
                db_file,
                exc_info=e,
            )
            return {}

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
        logging.info("Parsing from filesystem in %s", self.name)
        quarfiles = {}

        for idx, entry in enumerate(self.location.glob("{*}")):
            logging.debug('Parsing entry, idx %s, path "%s"', idx, entry)
            if not entry.is_file():
                logging.debug("Entry (idx %s) is not a file, skipping", idx)
                continue

            filename = entry.name

            if filename in data:
                logging.debug("Entry (idx %s) already found, skipping", idx)
                continue

            malfile = self._get_malfile(filename)

            entry_stat = parse(self).entry_stat(entry)
            if entry_stat is None:
                logging.debug('Skipping entry idx %s, path "%s"', idx, entry)
                continue
            timestamp = DTC.get_dt_from_stat(entry_stat)
            size = entry_stat.st_size

            q = QuarEntry()
            q.path = str(entry)
            q.timestamp = timestamp
            q.size = size
            q.threat = ThreatMetadata.UNKNOWN_THREAT
            q.malfile = malfile
            quarfiles[filename] = q

        return quarfiles
