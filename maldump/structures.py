from __future__ import annotations

from datetime import datetime as dt
import hashlib
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:
    from pathlib import Path

T = TypeVar("T")


class QuarEntry:
    timestamp: dt
    threat: str
    path: str
    size: int | None = None
    _md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    _malfile: bytes

    def __init__(self) -> None: ...

    @property
    def malfile(self) -> bytes:
        return self._malfile

    @malfile.setter
    def malfile(self, value: bytes) -> None:
        self._malfile = value
        if self._md5 is None:
            self._md5 = hashlib.md5(value).hexdigest()
        if self.sha1 is None:
            self.sha1 = hashlib.sha1(value).hexdigest()
        if self.sha256 is None:
            self.sha256 = hashlib.sha256(value).hexdigest()
        if self.size is None:
            self.size = len(value)

    @property
    def md5(self) -> str:
        if self._md5 is None:
            err_msg = "MD5 hash needs to be set"
            raise ValueError(err_msg)
        return self._md5

    @md5.setter
    def md5(self, value: str) -> None:
        self._md5 = value


class Quarantine(ABC):
    """Abstract class describing quarantines"""

    # Name of the AV
    name: str
    # Absolute location of the quarantine folder
    location: Path

    @abstractmethod
    def export(self) -> list[QuarEntry]: ...


class Parser(ABC, Generic[T]):
    """Abstract class describing parsers"""

    @abstractmethod
    def parse_from_log(
        self, data: dict[T, QuarEntry] | None = None
    ) -> dict[T, QuarEntry] | None: ...

    @abstractmethod
    def parse_from_fs(
        self, data: dict[T, QuarEntry] | None = None
    ) -> dict[T, QuarEntry] | None: ...

    def from_file(self, name: str, location: Path) -> list[QuarEntry]:
        """
        Template pattern function wrapper calling all the steps for retrieving
        quarantine entries.
        """
        self.name = name
        self.location = location
        data: dict[T, QuarEntry] = {}

        data_step = self.parse_from_log(data)
        if data_step is not None:
            data.update(data_step)

        data_step = self.parse_from_fs(data)
        if data_step is not None:
            data.update(data_step)

        return list(data.values())
