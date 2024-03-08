from __future__ import annotations

from pathlib import Path
from typing import List

from maldump.parsers.gdata_parser import GdataParser
from maldump.structures import Quarantine, QuarEntry


class GData(Quarantine):
    """Implements G Data quarantine format"""

    def __init__(self) -> None:
        super().__init__()
        self.name = 'G Data'
        self.location = Path('ProgramData/G Data/AVK/Quarantine')

    def export(self) -> List[QuarEntry]:
        quarfiles = GdataParser().from_file(
            name=self.name,
            location=self.location
        )

        return quarfiles
