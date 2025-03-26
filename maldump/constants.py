from enum import Enum


class OperatingSystem(Enum):
    WINDOWS = "windows"
    UNIX = "unix"
    LINUX = "linux"


class ThreatMetadata(str, Enum):
    UNKNOWN_THREAT = "Unknown-no-metadata"
