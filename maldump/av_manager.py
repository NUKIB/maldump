from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from maldump.avs import (
    avast,
    avg,
    avira,
    eset,
    forticlient,
    gdata,
    kaspersky,
    malwarebytes,
    mcafee,
    windef,
)

if TYPE_CHECKING:
    from maldump.structures import Quarantine


class AVManager:
    """Container class holding all instances"""

    avs: ClassVar[list[Quarantine]] = [
        windef.WindowsDefender(),
        forticlient.FortiClient(),
        malwarebytes.Malwarebytes(),
        gdata.GData(),
        avast.Avast(),
        avira.Avira(),
        kaspersky.Kaspersky(),
        eset.EsetNOD32(),
        mcafee.McAfee(),
        avg.AVG(),
    ]

    @classmethod
    def detect(cls) -> list[Quarantine]:
        """Returns a list of avs installed on the system"""
        return [av for av in cls.avs if av.location.exists()]

    @classmethod
    def retrieve(cls) -> list[Quarantine]:
        """Returns a list of all supported avs"""
        return cls.avs
