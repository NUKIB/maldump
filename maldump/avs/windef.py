from __future__ import annotations

from pathlib import Path
from typing import List

from maldump.parsers.windef_parser import WindowsDefenderParser
from maldump.structures import Quarantine, QuarEntry


class WindowsDefender(Quarantine):
    """Implements Windows Defender quarantine format"""

    def __init__(self) -> None:
        super().__init__()
        self.name = 'Microsoft Defender'
        self.location = Path(
            'ProgramData/Microsoft/Windows Defender/Quarantine')

    def export(self) -> List[QuarEntry]:
        quarfiles = WindowsDefenderParser().from_file(
            name=self.name,
            location=self.location
        )

        return quarfiles
