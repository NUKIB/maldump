from __future__ import annotations

from pathlib import Path
from typing import List

from maldump.parsers.avast_parser import AvastParser
from maldump.structures import Quarantine, QuarEntry


class Avast(Quarantine):
    """Implements Avast quarantine format"""

    def __init__(self) -> None:
        super().__init__()
        self.name = 'Avast'
        self.location = Path('ProgramData/Avast Software/Avast/chest')

    def export(self) -> List[QuarEntry]:
        quarfiles = AvastParser().from_file(
            name=self.name,
            location=self.location
        )

        return quarfiles
