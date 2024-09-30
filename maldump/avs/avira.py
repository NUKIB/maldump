from __future__ import annotations

from pathlib import Path

from maldump.parsers.avira_parser import AviraParser
from maldump.structures import Quarantine, QuarEntry


class Avira(Quarantine):
    """Implements Avira quarantine format"""

    def __init__(self) -> None:
        super().__init__()
        self.name = "Avira"
        self.location = Path("ProgramData/Avira/Antivirus/INFECTED")

    def export(self) -> list[QuarEntry]:
        return AviraParser().from_file(name=self.name, location=self.location)
