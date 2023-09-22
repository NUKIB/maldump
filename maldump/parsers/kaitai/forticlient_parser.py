# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import BytesIO, KaitaiStream, KaitaiStruct

if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (
        kaitaistruct.__version__))


class ForticlientParser(KaitaiStruct):
    """Creator: Nikola Knezevic
    License: CC-BY-SA-4.0 https://creativecommons.org/licenses/by-sa/4.0/
    """

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.magic = self._io.read_bytes(8)
        if not self.magic == b"\x51\x55\x41\x52\x46\x00\x00\x00":
            raise kaitaistruct.ValidationNotEqualError(
                b"\x51\x55\x41\x52\x46\x00\x00\x00", self.magic, self._io, u"/seq/0")
        self.unknown1 = self._io.read_u4le()
        self.mal_offset = self._io.read_u4le()
        self.unknown2 = self._io.read_bytes(36)
        self.mal_len = self._io.read_u4le()
        self._raw_timestamp = self._io.read_bytes(16)
        _io__raw_timestamp = KaitaiStream(BytesIO(self._raw_timestamp))
        self.timestamp = ForticlientParser.Timestamp(
            _io__raw_timestamp, self, self._root)
        self.unknown3 = self._io.read_bytes(12)
        self.file_id = self._io.read_u4le()
        self.len_mal_path = self._io.read_u4le()
        self.len_mal_type = self._io.read_u4le()
        self.mal_path = (self._io.read_bytes(
            self.len_mal_path)).decode(u"UTF-16LE")
        self.mal_type = (self._io.read_bytes(
            self.len_mal_type)).decode(u"UTF-16LE")
        self._raw_mal_file = self._io.read_bytes_full()
        self.mal_file = KaitaiStream.process_xor_one(self._raw_mal_file, 171)

    class Timestamp(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.year = self._io.read_u2le()
            self.month = self._io.read_u2le()
            self.tz_offset = self._io.read_u2le()
            self.day = self._io.read_u2le()
            self.hour = self._io.read_u2le()
            self.minute = self._io.read_u2le()
            self.second = self._io.read_u2le()
            self.microsecond = self._io.read_u2le()
