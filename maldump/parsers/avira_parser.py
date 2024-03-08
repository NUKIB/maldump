from datetime import datetime as dt
from hashlib import md5
from typing import List

from maldump.parsers.kaitai.avira_parser import AviraParser as KaitaiParser
from maldump.structures import QuarEntry


class AviraParser():

    def from_file(self, name, location) -> List[QuarEntry]:
        self.name = name
        self.location = location

        quarfiles = []
        for metafile in self.location.glob('*.qua'):
            kt = KaitaiParser.from_file(metafile)
            q = QuarEntry()
            q.timestamp = dt.fromtimestamp(kt.qua_time)
            q.threat = kt.mal_type
            q.path = kt.filename[4:]
            q.size = len(kt.mal_file)
            q.md5 = md5(kt.mal_file).digest().hex()
            q.malfile = kt.mal_file
            quarfiles.append(q)
            kt.close()

        return quarfiles
