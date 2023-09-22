# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import BytesIO, KaitaiStream, KaitaiStruct

if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (
        kaitaistruct.__version__))


class AviraParser(KaitaiStruct):
    """Creator: Florian Bausch, ERNW Research GmbH, https://ernw-research.de
    License: CC-BY-SA-4.0 https://creativecommons.org/licenses/by-sa/4.0/
    """

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.magic = self._io.read_bytes(16)
        if not self.magic == b"\x41\x6E\x74\x69\x56\x69\x72\x20\x51\x75\x61\x00\x00\x00\x00\x00":
            raise kaitaistruct.ValidationNotEqualError(
                b"\x41\x6E\x74\x69\x56\x69\x72\x20\x51\x75\x61\x00\x00\x00\x00\x00", self.magic, self._io, u"/seq/0")
        self.malicious_offset = self._io.read_u4le()
        self.len_filename = self._io.read_u4le()
        self.len_addl_info = self._io.read_u4le()
        self.unknown1 = self._io.read_bytes(32)
        self.qua_time = self._io.read_u4le()
        self.unknown2 = self._io.read_bytes(92)
        self.mal_type = (KaitaiStream.bytes_terminate(
            self._io.read_bytes(64), 0, False)).decode(u"UTF-8")
        self.filename = (self._io.read_bytes((self.len_filename if self.len_filename < 2 else (
            self.len_filename - 2)))).decode(u"UTF-16LE")
        if self.len_filename >= 2:
            self.padding1 = self._io.read_bytes(2)
            if not self.padding1 == b"\x00\x00":
                raise kaitaistruct.ValidationNotEqualError(
                    b"\x00\x00", self.padding1, self._io, u"/seq/9")

        self.addl_info = (self._io.read_bytes((self.len_addl_info if self.len_addl_info < 2 else (
            self.len_addl_info - 2)))).decode(u"UTF-16LE")
        if self.len_addl_info >= 2:
            self.padding2 = self._io.read_bytes(2)
            if not self.padding2 == b"\x00\x00":
                raise kaitaistruct.ValidationNotEqualError(
                    b"\x00\x00", self.padding2, self._io, u"/seq/11")

        self._raw_mal_file = self._io.read_bytes_full()
        self.mal_file = KaitaiStream.process_xor_one(self._raw_mal_file, 170)
