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
import logging
import re
import struct
from datetime import datetime, timezone
from pathlib import Path

from maldump.constants import ThreatMetadata
from maldump.parsers.kaitai.eset_ndf_parser import EsetNdfParser as KaitaiParserMetadata
from maldump.structures import Parser, QuarEntry
from maldump.utils import DatetimeConverter as DTC
from maldump.utils import Parser as parse
from maldump.utils import Reader as read

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


def log_fn(func):
    def wrapper(*args, **kwargs):
        logging.debug(
            "Calling function: %s, arguments: %s, keyword arguments: %s",
            func.__name__,
            tuple(
                (
                    arg
                    if type(arg) not in {bytes, EsetParser}
                    else "<" + type(arg).__name__ + ">"
                )
                for arg in args
            ),
            kwargs,
        )
        return func(*args, **kwargs)

    return wrapper


def _infoNotFound(field):
    logging.info("Parsing data in ESET led to field not found: %s", field)


def _warningUnexpected(field):
    logging.warning("Parsing data in ESET found unexpected bytes in field %s", field)


@log_fn
def _winToUnixTimestamp(winTimestamp):
    magicNumber = 11644473600
    return (winTimestamp / 10000000) - magicNumber


@log_fn
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


@log_fn
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


@log_fn
def _extractFirstSeen(rawRecord):
    # Format: FIRSTSEEN_HEADER + UnixTimestamp[4]

    offset = rawRecord.find(FIRSTSEEN_HEADER)
    if offset < 0:
        _infoNotFound("FirstSeen")
        return ""
    littleEndianTimestamp = rawRecord[offset + 4 : offset + 8]
    timestamp = struct.unpack("<L", littleEndianTimestamp)[0]
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime(TIMEFORMAT)


@log_fn
def _extractTimestamp(rawRecord):
    # Format: RECORD_HEADER + ID[4] + MicrosoftTimestamp[8]

    littleEndianTimestamp = rawRecord[4:12]
    winTimestamp = struct.unpack("<Q", littleEndianTimestamp)[0]
    timestamp = _winToUnixTimestamp(winTimestamp)
    return datetime.fromtimestamp(int(timestamp))


@log_fn
def _checkID(recordId, rawRecord):
    littleEndianIds = [rawRecord[0:4], rawRecord[16:20]]
    for littleEndianId in littleEndianIds:
        if struct.unpack("<L", littleEndianId)[0] != recordId:
            _warningUnexpected("ID")


@log_fn
def getRawRecords(rawData):
    rawRecords = rawData.split(RECORD_HEADER)[1:]
    if not rawRecords:
        logging.info("No records found in raw data")
        return []

    ziprecords = zip(range(len(rawRecords)), rawRecords)
    records = []
    for recordId, rawRecord in ziprecords:
        _checkID(recordId, rawRecord)
        # create 2D array instead of zip-object in Python 3
        records.append((recordId, rawRecord))
    return records


@log_fn
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


@log_fn
def mainParsing(virlog_path):
    virlog_data = read.contents(virlog_path, filetype="virlog")
    if virlog_data is None:
        return []

    rawRecords = getRawRecords(virlog_data)
    parsedRecords = []
    for idx, rawRecord in rawRecords:
        logging.debug("Parsing raw record %s/%s", idx + 1, len(rawRecords))
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

    @log_fn
    def _decrypt(self, data: bytes) -> bytes:
        return bytes([((b - 84) % 256) ^ 0xA5 for b in data])

    @log_fn
    def _get_malfile(self, username: str, sha1: str) -> bytes:
        quarfile = self.quarpath.format(username=username)
        quarfile = Path(quarfile) / (sha1.upper() + ".NQF")

        data = read.contents(quarfile, filetype="malware")
        if data is None:
            return b""

        return self._decrypt(data)

    @log_fn
    def _get_metadata(self, path: Path, objhash: str) -> KaitaiParserMetadata | None:
        # metadata file has .NDF extension
        metadata_path = path / (objhash + ".NDF")
        if not metadata_path.is_file():
            logging.debug("Metadata file not found")
            return None

        kt = parse(self).kaitai(KaitaiParserMetadata, metadata_path)
        if kt is None:
            return None

        kt.close()
        return kt

    def parse_from_log(self, _=None) -> dict[tuple[str, datetime], QuarEntry]:
        logging.info("Parsing from log in %s", self.name)
        quarfiles: dict[tuple[str, datetime], QuarEntry] = {}

        for idx, metadata in enumerate(mainParsing(self.location)):
            logging.debug("Parsing entry, idx %s", idx)
            if metadata["user"] == "SYSTEM":
                logging.debug("Entry's (idx %s) user is SYSTEM, skipping", idx)
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
        logging.info("Parsing from filesystem in %s", self.name)
        quarfiles = {}

        actual_path = Path("Users/")
        for idx, entry in enumerate(
            actual_path.glob("*/AppData/Local/ESET/ESET Security/Quarantine/*.NQF")
        ):
            logging.debug('Parsing entry, idx %s, path "%s"', idx, entry)
            res_path = re.match(self.regex_entry, entry.name)
            res_user = re.match(self.regex_user, str(entry))

            if not res_path:
                logging.debug(
                    "Entry's (idx %s) filename of incorrect format, skipping", idx
                )
                continue

            user = res_user.group(1)
            objhash = res_path.group(1)

            if (objhash.lower(), user) in data:
                logging.debug("Entry (idx %s) already found, skipping", idx)
                continue

            try:
                logging.debug('Trying to stat entry file, path "%s"', entry)
                entry_stat = entry.stat()
            except OSError as e:
                logging.exception(
                    'Cannot stat entry file, path "%s"', entry, exc_info=e
                )
                continue

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
