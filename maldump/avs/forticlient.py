from __future__ import annotations

from pathlib import Path
from typing import List

from maldump.parsers.forticlient_parser import ForticlientParser
from maldump.structures import Quarantine, QuarEntry


class FortiClient(Quarantine):
    """Implements FortiClient quarantine format"""

    def __init__(self) -> None:
        super().__init__()
        self.name = 'FortiClient'
        self.location = Path('Program Files/Fortinet/FortiClient/quarantine')

    def export(self) -> List[QuarEntry]:
        quarfiles = ForticlientParser().from_file(
            name=self.name,
            location=self.location
        )

        return quarfiles
