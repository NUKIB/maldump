from __future__ import annotations

from pathlib import Path
from typing import List

from maldump.parsers.eset_parser import EsetParser
from maldump.structures import Quarantine, QuarEntry


class EsetNOD32(Quarantine):
    """Implements Eset NOD32 quarantine format"""

    def __init__(self) -> None:
        super().__init__()
        self.name = 'Eset NOD32'
        # File containing metadata
        self.location = Path('ProgramData/ESET/ESET Security/Logs/virlog.dat')

    def export(self) -> List[QuarEntry]:
        quarfiles = EsetParser().from_file(
            name=self.name,
            location=self.location
        )

        return quarfiles
