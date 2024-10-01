from __future__ import annotations

from datetime import datetime as dt
from typing import TYPE_CHECKING

from maldump.parsers.kaitai.forticlient_parser import ForticlientParser as KaitaiParser
from maldump.structures import QuarEntry

if TYPE_CHECKING:
    from pathlib import Path


class ForticlientParser:
    def _normalize_path(self, path):
        if path[2:4] == "?\\":
            path = path[4:]
        return path

    def _get_time(self, ts):
        return dt(ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second)

    def from_file(self, name: str, location: Path) -> list[QuarEntry]:
        self.name = name
        self.location = location
        quarfiles = []

        for metafile in self.location.glob("*[!.meta]"):
            kt = KaitaiParser.from_file(metafile)
            q = QuarEntry()
            q.timestamp = self._get_time(kt.timestamp)
            q.threat = kt.mal_type
            q.path = self._normalize_path(kt.mal_path)
            q.size = kt.mal_len
            q.malfile = kt.mal_file
            quarfiles.append(q)
            kt.close()

        return quarfiles
