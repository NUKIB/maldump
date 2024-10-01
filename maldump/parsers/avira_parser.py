from __future__ import annotations

from datetime import datetime as dt
from typing import TYPE_CHECKING

from maldump.parsers.kaitai.avira_parser import AviraParser as KaitaiParser
from maldump.structures import QuarEntry

if TYPE_CHECKING:
    from pathlib import Path


class AviraParser:
    def from_file(self, name: str, location: Path) -> list[QuarEntry]:
        self.name = name
        self.location = location

        quarfiles = []
        for metafile in self.location.glob("*.qua"):
            kt = KaitaiParser.from_file(metafile)
            q = QuarEntry()
            q.timestamp = dt.fromtimestamp(kt.qua_time)
            q.threat = kt.mal_type
            q.path = kt.filename[4:]
            q.malfile = kt.mal_file
            quarfiles.append(q)
            kt.close()

        return quarfiles
