"""
Convenience utils for use in avs and parsers
"""

import contextlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Type, Generic, TypeVar

import kaitaistruct
from arc4 import ARC4

from maldump.constants import OperatingSystem

T = TypeVar("T")


def xor(plaintext: bytes, key: bytes) -> bytes:
    result = bytearray(plaintext)
    key_len = len(key)
    for i in range(len(plaintext)):
        result[i] ^= key[i % key_len]
    return bytes(result)


class CustomArc4:
    def __init__(self, key: bytes) -> None:
        self.key = bytes(key)

    def decode(self, plaintext: bytes) -> bytes:
        cipher = ARC4(self.key)
        return cipher.decrypt(plaintext)


class RawTimeConverter:
    def __init__(self, time_type: str):
        self.time_type = OperatingSystem(time_type)

    def _decode_windows(self, wintime_bytes: bytes) -> datetime:
        wintime = int.from_bytes(wintime_bytes, byteorder="little")
        magic_number = 11644473600
        timestamp = (wintime // 10000000) - magic_number
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)

    def _decode_unix(self, unixtime_bytes: bytes) -> datetime:
        timestamp = int.from_bytes(unixtime_bytes, byteorder="little")
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)

    def decode(self, time_bytes: bytes) -> datetime:
        if self.time_type == OperatingSystem.WINDOWS:
            return self._decode_windows(time_bytes)

        if self.time_type == OperatingSystem.UNIX:
            return self._decode_unix(time_bytes)

        raise NotImplementedError


class DatetimeConverter:
    @staticmethod
    # type: ignore
    def get_dt_from_stat(stat) -> datetime:
        logging.debug("Getting datetime from stat")
        ctime = stat.st_ctime_ns
        with contextlib.suppress(AttributeError):
            logging.debug("Trying to extract birthtime")
            ctime = stat.st_birthtime_ns
            logging.debug("Birthtime extracted successfully")

        return datetime.fromtimestamp(ctime // 1000000000)


class Parser(Generic[T]):
    def __init__(self, obj: object) -> None:
        self.objname = obj.__class__.__name__

    def kaitai(self, kaitai: Type[T], path: Path) -> T | None:
        kt = None
        try:
            logging.debug(
                'Trying to parse file on path "%s" to kaitai struct of type "%s" on <%s>',
                path,
                kaitai.__name__,
                self.objname,
            )
            kt = kaitai.from_file(path)
        except OSError as e:
            logging.exception(
                'Cannot open nor read kaitai for path "%s"',
                path,
                exc_info=e,
            )
        except kaitaistruct.KaitaiStructError as e:
            logging.warning(
                'Cannot read kaitai, probably incorrect format for path "%s"',
                path,
                exc_info=e,
            )
        return kt

    def timestamp(self, value: int) -> datetime:
        try:
            logging.debug(
                "Trying to convert timestamp on <%s>",
                self.objname,
            )
            timestamp = datetime.fromtimestamp(int(value))
        except (OSError, OverflowError, ValueError) as e:
            logging.warning(
                "Cannot convert timestamp to datetime, using default",
                exc_info=e,
            )
            timestamp = datetime.now()

        return timestamp


class Reader:
    @staticmethod
    def contents(path: Path, filetype: str = ""):
        if filetype:
            filetype += " "

        try:
            logging.debug('Trying to open %sfile, path "%s"', filetype, path)
            with open(path, "rb") as f:
                logging.debug('Trying to read %sfile, path "%s"', filetype, path)
                data = f.read()
        except OSError as e:
            logging.exception(
                'Cannot open %sfile in ESET on path "%s"', filetype, path, exc_info=e
            )
            data = None

        return data
