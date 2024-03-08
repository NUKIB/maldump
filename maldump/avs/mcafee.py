from __future__ import annotations

from pathlib import Path
from typing import List

from maldump.parsers.mcafee_parser import McafeeParser
from maldump.structures import Quarantine, QuarEntry


class McAfee(Quarantine):
    """Implements McAfee quarantine format"""

    def __init__(self) -> None:
        super().__init__()
        self.name = 'McAfee'
        self.location = Path(
            'ProgramData/McAfee/VirusScan/Quarantine/quarantine')

    def export(self) -> List[QuarEntry]:
        quarfiles = McafeeParser().from_file(
            name=self.name,
            location=self.location
        )

        return quarfiles
