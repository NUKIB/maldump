from datetime import datetime as dt
from hashlib import md5
from typing import List

from maldump.parsers.kaitai.windef_entries import \
    WindefEntries as KaitaiParserEntries
from maldump.parsers.kaitai.windef_resource_data import \
    WindefResourceData as KaitaiParserResourceData
from maldump.structures import QuarEntry


class WindowsDefenderParser():

    def _normalize(self, path_chrs):
        path_str = ''.join(map(chr, path_chrs[:-1]))
        if path_str[2:4] == '?\\':
            path_str = path_str[4:]
        return path_str

    def _get_malfile(self, guid):
        quarfile = self.location / 'ResourceData' / guid[:2] / guid
        kt = KaitaiParserResourceData.from_file(quarfile)
        malfile = kt.encryptedfile.mal_file
        kt.close()
        return malfile

    def from_file(self, name, location) -> List[QuarEntry]:
        self.name = name
        self.location = location
        quarfiles = []

        for metafile in self.location.glob('Entries/{*}'):
            kt = KaitaiParserEntries.from_file(metafile)
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
