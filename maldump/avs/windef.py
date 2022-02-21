from .quarantine import *
from maldump.parsers.windef_entries import WindefEntries
from maldump.parsers.windef_resource_data import WindefResourceData


class WindowsDefender(Quarantine):
    """Implements Windows Defender quarantine format"""

    def __init__(self):
        super().__init__()
        self.name = 'Microsoft Defender'
        self.location = Path('ProgramData/Microsoft/Windows Defender/Quarantine')

    def _normalize(self, path_chrs):
        path_str = ''.join(map(chr, path_chrs[:-1]))
        if path_str[2:4] == '?\\':
            path_str = path_str[4:]
        return path_str

    def _get_malfile(self, guid):
        quarfile = self.location / 'ResourceData' / guid[:2] / guid
        kt = WindefResourceData.from_file(quarfile)
        malfile = kt.encryptedfile.mal_file
        kt.close()
        return malfile

    def export(self):
        quarfiles = []
        for metafile in self.location.glob('Entries/{*}'):
            kt = WindefEntries.from_file(metafile)
            ts = dt.fromtimestamp(int(kt.data1.time.unixts))

            # Loop through all entries, if they exist
            for e in kt.data2.entries:
                # Support only 'file' type for now
                if e.entry.typestr == 'file':
                    guid = e.entry.element[0].content.value.hex().upper()
                    malfile = self._get_malfile(guid)
                    q = QuarEntry()
                    q.timestamp = ts
                    q.threat = kt.data1.mal_type
                    q.path = self._normalize(e.entry.path.character)
                    q.size = len(malfile)
                    q.md5 = md5(malfile).digest().hex()
                    q.malfile = malfile
                    quarfiles.append(q)
            kt.close()

        return quarfiles
