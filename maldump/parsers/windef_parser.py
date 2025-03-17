from __future__ import annotations

from datetime import datetime as dt
from typing import TYPE_CHECKING, Optional

from maldump.parsers.kaitai.windef_entries import WindefEntries as KaitaiParserEntries
from maldump.parsers.kaitai.windef_resource_data import (
    WindefResourceData as KaitaiParserResourceData,
)
from maldump.structures import QuarEntry, Parser
from maldump.utils import DatetimeConverter as DTC

if TYPE_CHECKING:
    from pathlib import Path


class WindowsDefenderParser(Parser):
    def _normalize(self, path_chrs) -> str:
        path_str = "".join(map(chr, path_chrs[:-1]))
        if path_str[2:4] == "?\\":
            path_str = path_str[4:]
        return path_str

    def _get_metadata(self, guid: str):
        quarfile = self.location / "ResourceData" / guid[:2] / guid
        kt = KaitaiParserResourceData.from_file(quarfile)
        kt.close()
        return kt

    def _get_malfile(self, guid: str) -> bytes:
        kt = self._get_metadata(guid)
        malfile = kt.encryptedfile.mal_file
        return malfile

    def parse_from_log(
        self, name: str, location: Path, data: Optional[dict[str, QuarEntry]] = None
    ) -> Optional[dict[str, QuarEntry]]:
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

        return quarfiles

    def parse_from_fs(
        self, name: str, location: Path, data: Optional[dict[str, QuarEntry]] = None
    ) -> Optional[dict[str, QuarEntry]]:
        quarfiles = {}

        # if the metadata are lost, but we still have access to data themselves
        for entry in self.location.glob("ResourceData/*/*"):
            if not entry.is_file():
                continue

            guid = entry.name

            if guid in data:
                continue

            entry_stat = entry.stat()
            timestamp = DTC.get_dt_from_stat(entry_stat)

            try:
                malfile = self._get_malfile(guid)
                kt_data = self._get_metadata(guid)
            # all IO errors, ValueError for incorrect structure,
            # kataistruct.*Exceptions for constants
            except Exception:
                continue

            q = QuarEntry()
            q.path = str(entry)
            q.timestamp = timestamp
            q.size = kt_data.encryptedfile.len_malfile
            q.threat = "Unknown-no-metadata"
            q.malfile = malfile

            quarfiles[guid] = q

        return quarfiles
