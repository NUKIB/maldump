"""
Convenience utils for use in avs and parsers
"""
from datetime import datetime, UTC

from arc4 import ARC4


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
        self.time_type = time_type

    def _decode_windows(self, wintime_bytes):
        wintime = int.from_bytes(wintime_bytes, byteorder="little")
        magic_number = 11644473600
        timestamp = (wintime // 10000000) - magic_number
        return datetime.fromtimestamp(timestamp, tz=UTC)

    def _decode_unix(self, unixtime_bytes):
        timestamp = int.from_bytes(unixtime_bytes, byteorder="little")
        return datetime.fromtimestamp(timestamp, tz=UTC)

    def decode(self, wintime_bytes: bytes) -> datetime:
        if self.time_type == "windows":
            return self._decode_windows(wintime_bytes)
        elif self.time_type == "unix":
            return self._decode_unix(wintime_bytes)
        else:
            raise NotImplementedError


class DatetimeConverter:
    @staticmethod
    def get_dt_from_stat(stat) -> datetime:
        ctime = stat.st_ctime_ns
        try:
            ctime = stat.st_birthtime_ns
        except AttributeError:
            # logging
            pass

        return datetime.fromtimestamp(ctime // 1000000000)
