"""
EsetLogParser: Python script for parsing ESET (NOD32) virlog.dat file.
Copyright (C) 2017 Ladislav Baco
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from maldump.constants import ThreatMetadata
from maldump.parsers.kaitai.eset_ndf_parser import EsetNdfParser as KaitaiParserMetadata
from maldump.parsers.kaitai.eset_virlog_parser import EsetVirlogParser
from maldump.structures import Parser, QuarEntry
from maldump.utils import DatetimeConverter as DTC

__author__ = "Ladislav Baco"
__copyright__ = "Copyright (C) 2017"
__credits__ = "Ladislav Baco"
__license__ = "GPLv3"
__version__ = "0.2.1"
__maintainer__ = "Ladislav Baco"
__status__ = "Development"


def parseRecord(record: dict):
    return {
        "timestamp": record.get("timestamp"),
        "virusdb": record.get("virus_db").str,
        "obj": record.get("object_name").str,
        "objhash": record.get("object_hash").hash.hex(),
        "infiltration": record.get("infiltration_name").str,
        "user": record.get("user_name").str.split("\\")[1],
        "progname": record.get("program_name").str,
        "proghash": record.get("program_hash").hash.hex(),
        "firstseen": record.get("firstseen"),
    }


def convertToDict(parser: EsetVirlogParser):
    values = [
        {
            **{
                y.name.name: y.arg if hasattr(y, "arg") else None
                for y in x.record.data_fields
            },
            **{"timestamp": x.record.win_timestamp.date_time},
        }
        for x in parser.threats
    ]

    return values


def mainParsing(virlog_path):
    parser = EsetVirlogParser.from_file(filename=virlog_path)
    threats = convertToDict(parser)

    parsedRecords = []
    for record in threats:
        parsedRecords.append(parseRecord(record))

    return parsedRecords


class EsetParser(Parser):
    def __init__(self):
        # Quarantine folder per user
        self.quarpath = "Users/{username}/AppData/Local/ESET/ESET Security/Quarantine/"
        self.regex_user = re.compile(
            r"Users[/\\]([^/\\]*)[/\\]AppData[/\\]Local[/\\]ESET[/\\]ESET Security[/\\]Quarantine[/\\]"  # noqa: E501
        )
        self.regex_entry = re.compile(r"([0-9a-fA-F]+)\.NQF$")

    def _decrypt(self, data: bytes) -> bytes:
        return bytes([((b - 84) % 256) ^ 0xA5 for b in data])

    def _get_malfile(self, username: str, sha1: str) -> bytes:
        quarfile = self.quarpath.format(username=username)
        quarfile = Path(quarfile) / (sha1.upper() + ".NQF")
        try:
            with open(quarfile, "rb") as f:
                data = f.read()
                decrypted_data = self._decrypt(data)
        except OSError:
            # logging
            print("Eset Error: could not read file", quarfile)

        return decrypted_data

    def _get_metadata(self, path: Path, objhash: str) -> KaitaiParserMetadata | None:
        # metadata file has .NDF extension
        metadata_path = path / (objhash + ".NDF")
        if not metadata_path.is_file():
            return None

        kt = KaitaiParserMetadata.from_file(metadata_path)
        kt.close()
        return kt

    def parse_from_log(self, _=None) -> dict[tuple[str, datetime], QuarEntry]:
        quarfiles: dict[tuple[str, datetime], QuarEntry] = {}

        for metadata in mainParsing(self.location):
            if metadata["user"] == "SYSTEM":
                continue
            q = QuarEntry()
            q.timestamp = metadata["timestamp"]
            q.threat = metadata["infiltration"]
            q.path = metadata["obj"]
            q.malfile = self._get_malfile(metadata["user"], metadata["objhash"])
            quarfiles[q.sha1, metadata["user"]] = q

        return quarfiles

    def parse_from_fs(
        self, data: dict[tuple[str, datetime], QuarEntry] | None = None
    ) -> dict[tuple[str, datetime], QuarEntry]:
        quarfiles = {}

        actual_path = Path("Users/")
        for entry in actual_path.glob(
            "*/AppData/Local/ESET/ESET Security/Quarantine/*.NQF"
        ):
            res_path = re.match(self.regex_entry, entry.name)
            res_user = re.match(self.regex_user, str(entry))

            if not res_path:
                continue

            user = res_user.group(1)
            objhash = res_path.group(1)

            if (objhash.lower(), user) in data:
                continue

            entry_stat = entry.stat()

            timestamp = DTC.get_dt_from_stat(entry_stat)
            path = str(entry)
            sha1 = None
            size = entry_stat.st_size
            threat = ThreatMetadata.UNKNOWN_THREAT

            kt = self._get_metadata(entry.parent, objhash)
            if kt is not None:
                timestamp = kt.datetime_unix.date_time
                path = kt.findings[0].mal_path.str
                sha1 = hex(int.from_bytes(kt.mal_hash_sha1, "big")).lstrip("0x")
                size = kt.mal_size
                threat = kt.findings[0].threat_canonized.str

            q = QuarEntry()
            q.timestamp = timestamp
            q.path = path
            q.sha1 = sha1
            q.size = size
            q.threat = threat
            q.malfile = self._get_malfile(user, objhash)

            quarfiles[q.sha1, user] = q

        return quarfiles
