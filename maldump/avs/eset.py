from .quarantine import *
from maldump.parsers.eset_parser import EsetParser


class EsetNOD32(Quarantine):
    """Implements Eset NOD32 quarantine format"""

    def __init__(self):
        super().__init__()
        self.name = 'Eset NOD32'
        # File containing metadata
        self.location = Path('ProgramData/ESET/ESET Security/Logs/virlog.dat')
        # Quarantine folder per user
        self.quarpath = 'Users/{username}/AppData/Local/ESET/ESET Security/Quarantine/'

    def _decrypt(self, data):
        return bytes([((b - 84) % 256) ^ 0xA5 for b in data])

    def _get_malfile(self, username, sha1):
        quarfile = self.quarpath.format(username=username)
        quarfile = Path(quarfile) / (sha1.upper() + '.NQF')
        try:
            with open(quarfile, 'rb') as f:
                data = f.read()
                decrypted_data = self._decrypt(data)
        except IOError:
            print('Eset Error: could not read file', quarfile)

        return decrypted_data

    def export(self):
        quarfiles = []
        for metadata in EsetParser(self.location):
            if metadata['user'] == 'SYSTEM':
                continue
            q = QuarEntry()
            q.timestamp = metadata['timestamp']
            q.threat = metadata['infiltration']
            q.path = metadata['obj']
            q.malfile = self._get_malfile(metadata['user'],
                                          metadata['objhash'])
            q.size = len(q.malfile)
            q.md5 = md5(q.malfile).digest().hex()
            quarfiles.append(q)

        return quarfiles
