from __future__ import annotations

import logging
import re
import zipfile
from datetime import datetime as dt
from typing import TypedDict
from zipfile import ZipFile

import defusedxml.ElementTree as ET

from maldump.structures import Parser, QuarEntry
from maldump.utils import Logger as log

logger = logging.getLogger(__name__)


class McafeeFileData(TypedDict):
    timestamp: str
    threat: str
    file_name: str
    size: str
    mal_file: bytes


class McafeeParser(Parser):
    """XML parser"""

    _zip_password = "infected"  # noqa: S105
    _re_xml = "[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}"

    _raw_malware = ""
    _xml_data = ""

    def parse_from_log(self, data=None):
        pass

    def parse_from_fs(
        self, _: dict[str, QuarEntry] | None = None
    ) -> dict[str, QuarEntry]:
        logger.info("Parsing from filesystem in %s", self.name)
        quarfiles = {}

        for idx, metafile in enumerate(self.location.glob("*.zip")):
            logger.debug('Parsing entry, idx %s, path "%s"', idx, metafile)
            parser = self._get_data(file_name=metafile)
            if parser is None:
                logger.debug('Skipping entry idx %s, path "%s"', idx, metafile)

            q = QuarEntry()
            q.timestamp = dt.strptime(parser["timestamp"], "%Y-%m-%d %H:%M:%S")
            q.threat = parser["threat"]
            q.path = parser["file_name"]
            q.size = int(parser["size"])
            q.malfile = parser["mal_file"]
            quarfiles[str(metafile)] = q

        return quarfiles

    @log.log(lgr=logger)
    def _get_data(self, file_name: str) -> McafeeFileData | None:
        # unzip file
        logger.debug('Checking if file is a ZIP file, path "%s"', file_name)
        if not zipfile.is_zipfile(filename=file_name):
            logger.warning(
                'File is not a ZIP file "%s" in class %s.', file_name, self.__name__
            )
            return None

        try:
            logger.debug('Trying to open a ZIP file, path "%s"', file_name)
            with ZipFile(file=file_name, mode="r") as archive:
                logger.debug("Setting a passford for a ZIP file")
                archive.setpassword(self._zip_password.encode())

                for idx, file in enumerate(archive.namelist()):
                    logger.debug('Traversing a ZIP file, idx %s, file: "%s"', idx, file)
                    # save files to private variables
                    text = archive.read(file).decode(encoding="utf-8")
                    if re.search(self._re_xml, text) and self._xml_data == "":
                        self._xml_data = text
                    elif self._raw_malware == "" and not re.search(self._re_xml, text):
                        self._raw_malware = text
                return self._read()

        except RuntimeError as e:
            logger.exception(
                'Cannot open a ZIP file on path "%s"', file_name, exc_info=e
            )

        return None

    @log.log(lgr=logger)
    def _read(self) -> McafeeFileData | None:
        try:
            logger.debug("Trying to parse an XML file from data in McAfee")
            root = ET.fromstring(self._xml_data)
        except ET.ParseError as e:
            logger.exception("Cannot parse an XML file in McAfee", exc_info=e)
            return None

        parser = {
            "timestamp": root.find("creationTime").text,
            "threat": root.find("detectionName").text,
            "file_name": root.find("Files/File/originalPath").text,
            "size": root.find("Files/File/size").text,
            "mal_file": bytes(self._raw_malware, "utf-8"),
        }

        return McafeeFileData(**parser)
