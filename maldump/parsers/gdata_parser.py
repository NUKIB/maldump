from datetime import datetime as dt
from hashlib import md5
from typing import List

from maldump.parsers.kaitai.gdata_parser import GdataParser as KaitaiParser
from maldump.structures import QuarEntry


class GdataParser():

    def from_file(self, name, location) -> List[QuarEntry]:
        self.name = name
        self.location = location
        quarfiles = []

        for metafile in self.location.glob('*.q'):
            kt = KaitaiParser.from_file(metafile)

            q = QuarEntry()
            q.timestamp = dt.fromtimestamp(kt.data1.quatime)
            q.threat = kt.data1.malwaretype.string_content
            q.path = kt.data2.path.string_content[4:]
            q.size = kt.data2.filesize
            q.md5 = md5(kt.mal_file).digest().hex()
            q.malfile = kt.mal_file
            quarfiles.append(q)
            kt.close()

        return quarfiles
