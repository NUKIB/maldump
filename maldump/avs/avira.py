from .quarantine import *
from maldump.parsers.avira_parser import AviraParser


class Avira(Quarantine):
    """Implements Avira quarantine format"""

    def __init__(self):
        super().__init__()
        self.name = 'Avira'
        self.location = Path('ProgramData/Avira/Antivirus/INFECTED')

    def export(self):
        quarfiles = []
        for metafile in self.location.glob('*.qua'):
            kt = AviraParser.from_file(metafile)
            q = QuarEntry()
            q.timestamp = dt.fromtimestamp(kt.qua_time)
            q.threat = kt.mal_type
            q.path = kt.filename[4:]
            q.size = len(kt.mal_file)
            q.md5 = md5(kt.mal_file).digest().hex()
            q.malfile = kt.mal_file
            quarfiles.append(q)

        return quarfiles
