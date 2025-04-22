from __future__ import annotations

import logging

from maldump.parsers.kaitai.avira_parser import AviraParser as KaitaiParser
from maldump.structures import Parser, QuarEntry
from maldump.utils import Parser as parse

logger = logging.getLogger(__name__)


class AviraParser(Parser):
    def parse_from_log(self, data=None):
        pass

    def parse_from_fs(self, _=None) -> dict[str, QuarEntry]:
        logger.info("Parsing from filesystem in %s", self.name)
        quarfiles = {}
        for idx, metafile in enumerate(self.location.glob("*.qua")):
            logger.debug('Parsing entry, idx %s, path "%s"', idx, metafile)

            kt = parse(self).kaitai(KaitaiParser, metafile)
            if kt is None:
                logger.debug('Skipping entry idx %s, path "%s"', idx, metafile)
                continue

            q = QuarEntry()

            q.timestamp = parse(self).timestamp(kt.qua_time)
            q.threat = kt.mal_type
            q.path = kt.filename[4:]
            q.malfile = kt.mal_file
            quarfiles[str(metafile)] = q
            kt.close()

        return quarfiles
