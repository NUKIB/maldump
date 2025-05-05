from __future__ import annotations

import logging

from maldump.parsers.kaitai.gdata_parser import GdataParser as KaitaiParser
from maldump.structures import Parser, QuarEntry
from maldump.utils import Parser as parse

logger = logging.getLogger(__name__)


class GdataParser(Parser):
    def parse_from_log(self, data=None):
        pass

    def parse_from_fs(self, _=None) -> dict[str, QuarEntry]:
        logger.info("Parsing from filesystem in %s", self.name)
        quarfiles = {}

        for idx, metafile in enumerate(self.location.glob("*.q")):
            logger.debug('Parsing entry, idx %s, path "%s"', idx, metafile)

            kt = parse(self).kaitai(KaitaiParser, metafile)
            if kt is None:
                logger.debug('Skipping entry idx %s, path "%s"', idx, metafile)
                continue

            q = QuarEntry(self)
            q.timestamp = parse(self).timestamp(kt.data1.quatime)
            q.threat = kt.data1.malwaretype.string_content
            q.path = kt.data2.path.string_content[4:]
            q.size = kt.data2.filesize
            q.malfile = kt.mal_file
            quarfiles[str(metafile)] = q
            kt.close()

        return quarfiles
