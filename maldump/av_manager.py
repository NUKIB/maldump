from __future__ import annotations

from typing import List

from maldump.avs import (avast, avg, avira, eset, forticlient, gdata,
                         kaspersky, malwarebytes, mcafee, windef)
from maldump.structures import Quarantine


class AVManager():
    """Container class holding all instances"""
    avs: List[Quarantine] = [
        windef.WindowsDefender(),
        forticlient.FortiClient(),
        malwarebytes.Malwarebytes(),
        gdata.GData(),
        avast.Avast(),
        avira.Avira(),
        kaspersky.Kaspersky(),
        eset.EsetNOD32(),
        mcafee.McAfee(),
        avg.AVG()
    ]

    @classmethod
    def detect(cls) -> List[Quarantine]:
        """Returns a list of avs installed on the system"""
        return [av for av in cls.avs if av.location.exists()]
