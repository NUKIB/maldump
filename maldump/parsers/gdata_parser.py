from __future__ import annotations

from datetime import datetime as dt
from typing import TYPE_CHECKING

from maldump.parsers.kaitai.gdata_parser import GdataParser as KaitaiParser
from maldump.structures import QuarEntry, Parser

if TYPE_CHECKING:
    from pathlib import Path


class GdataParser(Parser):

    def parse_from_log(self, name, location, data=None):
        pass

    def parse_from_fs(self, name: str, location: Path, data: dict[str, QuarEntry] = None) -> dict[str, QuarEntry]:
        quarfiles = {}

        for metafile in self.location.glob("*.q"):
            kt = KaitaiParser.from_file(metafile)

            q = QuarEntry()
            q.timestamp = dt.fromtimestamp(kt.data1.quatime)
            q.threat = kt.data1.malwaretype.string_content
            q.path = kt.data2.path.string_content[4:]
            q.size = kt.data2.filesize
            q.malfile = kt.mal_file
            quarfiles[str(metafile)] = q
            kt.close()

        return quarfiles
