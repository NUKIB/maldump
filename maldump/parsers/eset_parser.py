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

import binascii
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

from maldump.constants import ThreatMetadata
from maldump.parsers.kaitai.eset_ndf_parser import EsetNdfParser as KaitaiParserMetadata
from maldump.structures import Parser, QuarEntry
from maldump.utils import DatetimeConverter as DTC

__author__ = "Ladislav Baco"
__copyright__ = "Copyright (C) 2017"
__credits__ = "Ladislav Baco"
__license__ = "GPLv3"
__version__ = "0.2.1"
__maintainer__ = "Ladislav Baco"
__status__ = "Development"

TIMEFORMAT = "%Y-%m-%d %H:%M:%S"
NULL = b"\x00\x00"
RECORD_HEADER = b"\x24\x00\x00\x00\x01\x00\x01\x00"
OBJECT_HEADER = b"\xbe\x0b\x4e\x00"
INFILTRATION_HEADER = b"\x4d\x1d\x4e\x00"
USER_HEADER = b"\xee\x03\x4e\x00"
VIRUSDB_HEADER = b"\x17\x27\x4e\x00"
PROGNAME_HEADER = b"\xc4\x0b\x4e\x00"
PROGHASH_HEADER = b"\x9d\x13\x42\x00"
OBJECTHASH_HEADER = b"\x9e\x13\x42\x00"
FIRSTSEEN_HEADER = b"\x9f\x13\x46\x00"

_dataTypeHeaders = {
    "Object": OBJECT_HEADER,
    "Infiltration": INFILTRATION_HEADER,
    "User": USER_HEADER,
    "VirusDB": VIRUSDB_HEADER,
    "ProgName": PROGNAME_HEADER,
}
_hashTypeHeaders = {"ObjectHash": OBJECTHASH_HEADER, "ProgHash": PROGHASH_HEADER}


def eprint(*args, **kwargs):
    """Prints debug messages to stderr"""
    print(*args, file=sys.stderr, **kwargs)


def _infoNotFound(field):
    eprint("Eset Info: field not found: " + field)


def _warningUnexpected(field):
    eprint("Eset Warning: unexpected bytes in field " + field)


def _winToUnixTimestamp(winTimestamp):
    magicNumber = 11644473600
    return (winTimestamp / 10000000) - magicNumber


def _extractDataType(dataType, rawRecord):
    # Format: dataType_HEADER + '??' + NULL + objectData + NULL

    dataType_HEADER = _dataTypeHeaders[dataType]
    dataOffset = rawRecord.find(dataType_HEADER)
    if dataOffset < 0:
        _infoNotFound(dataType)
        return ""
    if rawRecord[dataOffset + 6 : dataOffset + 8] != NULL:
        _warningUnexpected(dataType)
    # find NULL char, but search for (\x00)*3, because third zero byte is part of
    # last widechar
    dataEnd = dataOffset + 8 + 1 + rawRecord[dataOffset + 8 :].find(b"\x00" + NULL)
    dataWideChar = rawRecord[dataOffset + 8 : dataEnd]
    return dataWideChar.decode("utf-16")


def _extractHashType(hashType, rawRecord):
    # Format: hashType_HEADER + '??' + NULL + hashData[20]

    hashType_HEADER = _hashTypeHeaders[hashType]
    hashOffset = rawRecord.find(hashType_HEADER)
    if hashOffset < 0:
        _infoNotFound(hashType)
        return ""
    if rawRecord[hashOffset + 6 : hashOffset + 8] != NULL:
        _warningUnexpected(hashType)
    hashEnd = hashOffset + 8 + 20
    hashHex = rawRecord[hashOffset + 8 : hashEnd]
    # return hashHex.encode('hex')
    return binascii.hexlify(hashHex).decode("utf-8")


def _extractFirstSeen(rawRecord):
    # Format: FIRSTSEEN_HEADER + UnixTimestamp[4]

    offset = rawRecord.find(FIRSTSEEN_HEADER)
    if offset < 0:
        _infoNotFound("FirstSeen")
        return ""
    littleEndianTimestamp = rawRecord[offset + 4 : offset + 8]
    timestamp = struct.unpack("<L", littleEndianTimestamp)[0]
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime(TIMEFORMAT)


def _extractTimestamp(rawRecord):
    # Format: RECORD_HEADER + ID[4] + MicrosoftTimestamp[8]

    littleEndianTimestamp = rawRecord[4:12]
    winTimestamp = struct.unpack("<Q", littleEndianTimestamp)[0]
    timestamp = _winToUnixTimestamp(winTimestamp)
    return datetime.fromtimestamp(int(timestamp))


def _checkID(recordId, rawRecord):
    littleEndianIds = [rawRecord[0:4], rawRecord[16:20]]
    for littleEndianId in littleEndianIds:
        if struct.unpack("<L", littleEndianId)[0] != recordId:
            _warningUnexpected("ID")


def getRawRecords(rawData):
    rawRecords = rawData.split(RECORD_HEADER)[1:]
    ziprecords = zip(range(len(rawRecords)), rawRecords)
    records = []
    for recordId, rawRecord in ziprecords:
        _checkID(recordId, rawRecord)
        # create 2D array instead of zip-object in Python 3
        records.append((recordId, rawRecord))
    return records


def parseRecord(rawRecord):
    return {
        "timestamp": _extractTimestamp(rawRecord),
        "virusdb": _extractDataType("VirusDB", rawRecord),
        "obj": _extractDataType("Object", rawRecord),
        "objhash": _extractHashType("ObjectHash", rawRecord),
        "infiltration": _extractDataType("Infiltration", rawRecord),
        "user": _extractDataType("User", rawRecord).split("\\")[1],
        "progname": _extractDataType("ProgName", rawRecord),
        "proghash": _extractHashType("ProgHash", rawRecord),
        "firstseen": _extractFirstSeen(rawRecord),
    }


def mainParsing(virlog_path):
    with open(virlog_path, "rb") as f:
        virlog_data = f.read()
    rawRecords = getRawRecords(virlog_data)
    parsedRecords = []
    for _, rawRecord in rawRecords:
        parsedRecords.append(parseRecord(rawRecord))

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
                path = kt.findings[0].mal_path.str_cont
                sha1 = hex(int.from_bytes(kt.mal_hash_sha1, "big")).lstrip("0x")
                size = kt.mal_size
                threat = kt.findings[0].threat_canonized.str_cont

            q = QuarEntry()
            q.timestamp = timestamp
            q.path = path
            q.sha1 = sha1
            q.size = size
            q.threat = threat
            q.malfile = self._get_malfile(user, objhash)

            quarfiles[q.sha1, user] = q

        return quarfiles
