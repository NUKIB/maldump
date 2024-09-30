from __future__ import annotations

from datetime import datetime as dt
from hashlib import md5
from typing import TYPE_CHECKING

from maldump.parsers.kaitai.gdata_parser import GdataParser as KaitaiParser
from maldump.structures import QuarEntry

if TYPE_CHECKING:
    from pathlib import Path


class GdataParser:
    def from_file(self, name: str, location: Path) -> list[QuarEntry]:
        self.name = name
        self.location = location
        quarfiles = []

        for metafile in self.location.glob("*.q"):
            kt = KaitaiParser.from_file(metafile)

            q = QuarEntry()
            q.timestamp = dt.fromtimestamp(kt.data1.quatime)
            q.threat = kt.data1.malwaretype.string_content
            q.path = kt.data2.path.string_content[4:]
            q.size = kt.data2.filesize
            q.md5 = md5(kt.mal_file).hexdigest()
            q.malfile = kt.mal_file
            quarfiles.append(q)
            kt.close()

        return quarfiles
