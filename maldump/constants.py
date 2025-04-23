from enum import Enum
from typing import Any
from xml.etree.ElementTree import Element

import maldump.parsers


class OperatingSystem(Enum):
    WINDOWS = "windows"
    UNIX = "unix"
    LINUX = "linux"


class ThreatMetadata(str, Enum):
    UNKNOWN_THREAT = "Unknown-no-metadata"


class UnloggedObjects(object):
    _unlogged = {
        bytes,
        maldump.parsers.eset_parser.EsetParser,
        maldump.parsers.avast_parser.AvastParser,
        maldump.parsers.avg_parser.AVGParser,
        maldump.parsers.forticlient_parser.ForticlientParser,
        maldump.parsers.kaspersky_parser.KasperskyParser,
        maldump.parsers.malwarebytes_parser.MalwarebytesParser,
        maldump.parsers.mcafee_parser.McafeeParser,
        maldump.parsers.windef_parser.WindowsDefenderParser,
        maldump.parsers.kaitai.forticlient_parser.ForticlientParser.Timestamp,
        Element,
    }

    @classmethod
    def __contains__(cls, item: Any) -> bool:
        return item in cls._unlogged
