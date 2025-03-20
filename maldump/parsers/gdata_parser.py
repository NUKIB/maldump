from __future__ import annotations

from datetime import datetime as dt

from maldump.parsers.kaitai.gdata_parser import GdataParser as KaitaiParser
from maldump.structures import Parser, QuarEntry


class GdataParser(Parser):

    def parse_from_log(self, data=None):
        pass

    def parse_from_fs(self, _=None) -> dict[str, QuarEntry]:
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
