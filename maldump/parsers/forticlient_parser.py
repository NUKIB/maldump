from __future__ import annotations

from datetime import datetime as dt
from typing import TYPE_CHECKING

from maldump.parsers.kaitai.forticlient_parser import ForticlientParser as KaitaiParser
from maldump.structures import QuarEntry, Parser

if TYPE_CHECKING:
    from pathlib import Path


class ForticlientParser(Parser):
    def _normalize_path(self, path):
        if path[2:4] == "?\\":
            path = path[4:]
        return path

    def _get_time(self, ts):
        return dt(ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second)

    def parse_from_log(self, name, location, data=None):
        pass

    def parse_from_fs(self, name: str, location: Path, data: dict[str, QuarEntry] = None) -> dict[str, QuarEntry]:
        quarfiles = {}

        for metafile in self.location.glob("*[!.meta]"):
            kt = KaitaiParser.from_file(metafile)
            q = QuarEntry()
            q.timestamp = self._get_time(kt.timestamp)
            q.threat = kt.mal_type
            q.path = self._normalize_path(kt.mal_path)
            q.size = kt.mal_len
            q.malfile = kt.mal_file
            quarfiles[str(metafile)] = q
            kt.close()

        return quarfiles
