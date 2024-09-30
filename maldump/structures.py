from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime as dt
from pathlib import Path


class QuarEntry:
    timestamp: dt
    threat: str
    path: str
    size: int
    md5: str
    malfile: bytes

    def __init__(self) -> None: ...


class Quarantine(ABC):
    """Abstract class describing quarantines"""

    # Name of the AV
    name: str
    # Absolute location of the quarantine folder
    location: Path

    @abstractmethod
    def __init__(self) -> None: ...

    @abstractmethod
    def export(self) -> list[QuarEntry]: ...


class Parser(ABC):
    """Abstract class describing parsers"""

    @abstractmethod
    def from_file(self, name: str, location: str) -> list[QuarEntry]: ...
