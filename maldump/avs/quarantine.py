from pathlib import Path
from hashlib import md5
from datetime import datetime as dt


class QuarEntry():
    def __init__(self):
        self.timestamp = ''  # datetime
        self.threat = ''     # string
        self.path = ''       # string
        self.size = ''       # integer
        self.md5 = ''        # string
        self.malfile = ''    # bytes-like


class Quarantine(object):
    """Generic class describing the overall quarantine interface"""

    def __init__(self):
        # Name of the AV
        self.name = ''

        # Absolute location of the quarantine folder
        self.location = Path()

    """Interface for the export function

    Returns:
        A list of 'QuarEntry' objects
    """
    def export(self):
        pass
