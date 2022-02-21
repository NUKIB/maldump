from .quarantine import *
from maldump.parsers.gdata_parser import GdataParser


class GData(Quarantine):
    """Implements G Data quarantine format"""

    def __init__(self):
        super().__init__()
        self.name = 'G Data'
        self.location = Path('ProgramData/G Data/AVK/Quarantine')

    def export(self):
        quarfiles = []
        for metafile in self.location.glob('*.q'):
            kt = GdataParser.from_file(metafile)

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
