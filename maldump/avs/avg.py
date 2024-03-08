from __future__ import annotations

from pathlib import Path
from typing import List

from maldump.parsers.avg_parser import AVGParser
from maldump.structures import Quarantine, QuarEntry


class AVG(Quarantine):
    """Implements AVG quarantine format"""

    def __init__(self) -> None:
        super().__init__()
        self.name = 'AVG'
        self.location = Path('ProgramData/AVG/Antivirus/chest')

    def export(self) -> List[QuarEntry]:
        quarfiles = AVGParser().from_file(
            name=self.name,
            location=self.location
        )

        return quarfiles
