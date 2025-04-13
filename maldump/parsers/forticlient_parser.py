from __future__ import annotations

import logging
from datetime import datetime as dt

from maldump.parsers.kaitai.forticlient_parser import ForticlientParser as KaitaiParser
from maldump.structures import Parser, QuarEntry
from maldump.utils import Parser as parse


def log_fn(func):
    def wrapper(*args, **kwargs):
        logging.debug(
            "Calling function: %s, arguments: %s, keyword arguments: %s",
            func.__name__,
            tuple(
                (
                    arg
                    if type(arg)
                    not in {bytes, ForticlientParser, KaitaiParser.Timestamp}
                    else "<" + type(arg).__name__ + ">"
                )
                for arg in args
            ),
            kwargs,
        )
        return func(*args, **kwargs)

    return wrapper


class ForticlientParser(Parser):
    @log_fn
    def _normalize_path(self, path):
        if path[2:4] == "?\\":
            path = path[4:]
        return path

    @log_fn
    def _get_time(self, ts):
        return dt(ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second)

    def parse_from_log(self, data=None):
        pass

    def parse_from_fs(self, _=None) -> dict[str, QuarEntry]:
        logging.info("Parsing from log in %s", self.name)
        quarfiles = {}

        for idx, metafile in enumerate(self.location.glob("*[!.meta]")):
            logging.debug('Parsing entry, idx %s, path "%s"', idx, metafile)

            kt = parse(self).kaitai(KaitaiParser, metafile)
            if kt is None:
                logging.debug('Skipping entry idx %s, path "%s"', idx, metafile)
                continue

            q = QuarEntry()
            q.timestamp = self._get_time(kt.timestamp)
            q.threat = kt.mal_type
            q.path = self._normalize_path(kt.mal_path)
            q.size = kt.mal_len
            q.malfile = kt.mal_file
            quarfiles[str(metafile)] = q
            kt.close()

        return quarfiles
