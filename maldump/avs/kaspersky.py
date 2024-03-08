from __future__ import annotations

from pathlib import Path
from typing import List

from maldump.parsers.kaspersky_parser import KasperskyParser
from maldump.structures import Quarantine, QuarEntry


class Kaspersky(Quarantine):
    """Implements Kaspersky quarantine format"""

    def __init__(self) -> None:
        super().__init__()
        self.name = 'Kaspersky for Windows Server'
        self.location = Path(
            'ProgramData/Kaspersky Lab/Kaspersky Security for Windows Server' +
            '/11.0/Quarantine'
        )

    def export(self) -> List[QuarEntry]:
        quarfiles = KasperskyParser().from_file(
            name=self.name,
            location=self.location
        )

        return quarfiles
