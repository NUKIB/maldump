from maldump.avs import *


class AVManager():
    """Container class holding all instances"""
    avs = [
        windef.WindowsDefender(),
        forticlient.FortiClient(),
        malwarebytes.Malwarebytes(),
        gdata.GData(),
        avast.Avast(),
        avira.Avira(),
        kaspersky.Kaspersky(),
        eset.EsetNOD32()
    ]

    @classmethod
    def detect(cls):
        """Returns a list of avs installed on the system"""
        return [av for av in cls.avs if av.location.exists()]
