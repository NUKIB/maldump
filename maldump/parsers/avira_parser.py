from __future__ import annotations

from datetime import datetime as dt

from maldump.parsers.kaitai.avira_parser import AviraParser as KaitaiParser
from maldump.structures import Parser, QuarEntry


class AviraParser(Parser):
    def parse_from_log(self, _=None) -> dict[str, QuarEntry]:
        quarfiles = {}
        for metafile in self.location.glob("*.qua"):
            kt = KaitaiParser.from_file(metafile)
            q = QuarEntry()
            q.timestamp = dt.fromtimestamp(kt.qua_time)
            q.threat = kt.mal_type
            q.path = kt.filename[4:]
            q.malfile = kt.mal_file
            quarfiles[str(metafile)] = q
            kt.close()

        return quarfiles

    def parse_from_fs(self, data=None):
        pass
