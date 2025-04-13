from __future__ import annotations

import logging
from datetime import datetime as dt

from kaitaistruct import KaitaiStructError

from maldump.constants import ThreatMetadata
from maldump.parsers.kaitai.windef_entries import WindefEntries as KaitaiParserEntries
from maldump.parsers.kaitai.windef_resource_data import (
    WindefResourceData as KaitaiParserResourceData,
)
from maldump.structures import Parser, QuarEntry
from maldump.utils import DatetimeConverter as DTC
from maldump.utils import Parser as parse


def log_fn(func):
    def wrapper(*args, **kwargs):
        logging.debug(
            "Calling function: %s, arguments: %s, keyword arguments: %s",
            func.__name__,
            tuple(
                (
                    arg
                    if type(arg) not in {bytes, WindowsDefenderParser}
                    else "<" + type(arg).__name__ + ">"
                )
                for arg in args
            ),
            kwargs,
        )
        return func(*args, **kwargs)

    return wrapper


class WindowsDefenderParser(Parser):
    @log_fn
    def _normalize(self, path_chrs) -> str:
        path_str = "".join(map(chr, path_chrs[:-1]))
        if path_str[2:4] == "?\\":
            path_str = path_str[4:]
        return path_str

    @log_fn
    def _get_metadata(self, guid: str):
        quarfile = self.location / "ResourceData" / guid[:2] / guid

        kt = parse(self).kaitai(KaitaiParserResourceData, quarfile)
        if kt is not None:
            kt.close()

        return kt

    @log_fn
    def _get_malfile(self, guid: str) -> bytes:
        kt = self._get_metadata(guid)
        if kt is None:
            return b""
        return kt.encryptedfile.mal_file

    def parse_from_log(self, _=None) -> dict[str, QuarEntry]:
        logging.info("Parsing from log in %s", self.name)
        quarfiles = {}

        for idx, metafile in enumerate(self.location.glob("Entries/{*}")):
            logging.debug('Parsing entry, idx %s, path "%s"', idx, metafile)
            kt = parse(self).kaitai(KaitaiParserEntries, metafile)
            if kt is None:
                logging.debug('Skipping entry idx %s, path "%s"', idx, metafile)
                continue

            ts = parse(self).timestamp(kt.data1.time.unixts)

            # Loop through all entries, if they exist
            for idx_e, e in enumerate(kt.data2.entries):
                logging.debug("Parsing entry inside metadata file, idx_e %s", idx_e)
                # Support only 'file' type for now
                if e.entry.typestr != "file":
                    logging.debug("Entry (idx_e %s) is not a file, skipping", idx_e)
                    continue

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
        self, data: dict[str, QuarEntry] | None = None
    ) -> dict[str, QuarEntry]:
        logging.info("Parsing from filesystem in %s", self.name)
        quarfiles = {}

        # if the metadata are lost, but we still have access to data themselves
        for idx, entry in enumerate(self.location.glob("ResourceData/*/*")):
            logging.debug('Parsing entry, idx %s, path "%s"', idx, entry)
            if not entry.is_file():
                logging.debug("Entry (idx %s) is not a file, skipping", idx)
                continue

            guid = entry.name

            if guid in data:
                logging.debug("Entry (idx %s) already found, skipping", idx)
                continue

            entry_stat = parse(self).entry_stat(entry)
            if entry_stat is None:
                logging.debug('Skipping entry idx %s, path "%s"', idx, entry)
                continue
            timestamp = DTC.get_dt_from_stat(entry_stat)

            malfile = self._get_malfile(guid)
            kt_data = self._get_metadata(guid)

            if malfile is None:
                logging.debug('Skipping entry idx %s, path "%s"', idx, entry)
                continue

            q = QuarEntry()
            q.path = str(entry)
            q.timestamp = timestamp
            q.size = kt_data.encryptedfile.len_malfile
            q.threat = ThreatMetadata.UNKNOWN_THREAT
            q.malfile = malfile

            quarfiles[guid] = q

        return quarfiles
