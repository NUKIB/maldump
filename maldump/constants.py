from enum import Enum
from typing import Any
from xml.etree.ElementTree import Element


class OperatingSystem(Enum):
    WINDOWS = "windows"
    UNIX = "unix"
    LINUX = "linux"


class ThreatMetadata(str, Enum):
    UNKNOWN_THREAT = "Unknown-no-metadata"


class UnloggedObjects:
    @staticmethod
    def __contains__(item: Any) -> bool:
        from maldump.parsers.avast_parser import AvastParser
        from maldump.parsers.avg_parser import AVGParser
        from maldump.parsers.eset_parser import EsetParser
        from maldump.parsers.forticlient_parser import ForticlientParser
        from maldump.parsers.kaitai.eset_virlog_parser import EsetVirlogParser
        from maldump.parsers.kaitai.forticlient_parser import (
            ForticlientParser as ForticlientKaitaiParser,
        )
        from maldump.parsers.kaspersky_parser import KasperskyParser
        from maldump.parsers.malwarebytes_parser import MalwarebytesParser
        from maldump.parsers.mcafee_parser import McafeeParser
        from maldump.parsers.windef_parser import WindowsDefenderParser

        unlogged = {
            bytes,
            EsetParser,
            EsetVirlogParser,
            EsetVirlogParser.Widestr,
            AvastParser,
            AVGParser,
            ForticlientParser,
            KasperskyParser,
            MalwarebytesParser,
            McafeeParser,
            WindowsDefenderParser,
            ForticlientKaitaiParser.Timestamp,
            Element,
        }

        return item in unlogged
