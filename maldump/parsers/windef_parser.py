from __future__ import annotations

import os
from datetime import datetime as dt
from typing import TYPE_CHECKING

from maldump.parsers.kaitai.windef_entries import WindefEntries as KaitaiParserEntries
from maldump.parsers.kaitai.windef_resource_data import (
    WindefResourceData as KaitaiParserResourceData,
)
from maldump.structures import QuarEntry, Parser

if TYPE_CHECKING:
    from pathlib import Path


class WindowsDefenderParser(Parser):
    def _normalize(self, path_chrs) -> str:
        path_str = "".join(map(chr, path_chrs[:-1]))
        if path_str[2:4] == "?\\":
            path_str = path_str[4:]
        return path_str

    def _get_malfile(self, guid: str) -> bytes:
        quarfile = self.location / "ResourceData" / guid[:2] / guid
        kt = KaitaiParserResourceData.from_file(quarfile)
        malfile = kt.encryptedfile.mal_file
        kt.close()
        return malfile

    def from_file(self, name: str, location: Path) -> list[QuarEntry]:
        self.name = name
        self.location = location
        quarfiles = {}

        for metafile in self.location.glob("Entries/{*}"):
            kt = KaitaiParserEntries.from_file(metafile)
            ts = dt.fromtimestamp(int(kt.data1.time.unixts))

            # Loop through all entries, if they exist
            for e in kt.data2.entries:
                # Support only 'file' type for now
                if e.entry.typestr == "file":
                    guid = e.entry.element[0].content.value.hex().upper()
                    malfile = self._get_malfile(guid)
                    q = QuarEntry()
                    q.timestamp = ts
                    q.threat = kt.data1.mal_type
                    q.path = self._normalize(e.entry.path.character)
                    q.malfile = malfile
                    quarfiles[guid] = q
            kt.close()

        # if the metadata are lost, but we still have access to data themselves
        for entry in self.location.glob("ResourceData/*/*"):
            guid = entry.name

            if guid in quarfiles:
                continue

            try:
                malfile = self._get_malfile(guid)
            # all IO errors, ValueError for incorrect structure,
            # kataistruct.*Exceptions for constants
            except Exception:
                continue

            q = QuarEntry()
            q.malfile = malfile
            q.path = str(entry)

            quarfiles[guid] = q

        return list(quarfiles.values())
