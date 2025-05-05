from __future__ import annotations

import logging
from datetime import datetime as dt

from maldump.parsers.kaitai.forticlient_parser import ForticlientParser as KaitaiParser
from maldump.structures import Parser, QuarEntry
from maldump.utils import Logger as log
from maldump.utils import Parser as parse

logger = logging.getLogger(__name__)


class ForticlientParser(Parser):
    @log.log(lgr=logger)
    def _normalize_path(self, path):
        if path[2:4] == "?\\":
            path = path[4:]
        return path

    @log.log(lgr=logger)
    def _get_time(self, ts):
        return dt(ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second)

    def parse_from_log(self, data=None):
        pass

    def parse_from_fs(self, _=None) -> dict[str, QuarEntry]:
        logger.info("Parsing from log in %s", self.name)
        quarfiles = {}

        for idx, metafile in enumerate(self.location.glob("*[!.meta]")):
            logger.debug('Parsing entry, idx %s, path "%s"', idx, metafile)

            kt = parse(self).kaitai(KaitaiParser, metafile)
            if kt is None:
                logger.debug('Skipping entry idx %s, path "%s"', idx, metafile)
                continue

            q = QuarEntry(self)
            q.timestamp = self._get_time(kt.timestamp)
            q.threat = kt.mal_type
            q.path = self._normalize_path(kt.mal_path)
            q.size = kt.mal_len
            q.malfile = kt.mal_file
            quarfiles[str(metafile)] = q
            kt.close()

        return quarfiles
