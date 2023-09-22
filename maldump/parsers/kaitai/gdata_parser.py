# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import BytesIO, KaitaiStream, KaitaiStruct

import maldump.utils

if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (
        kaitaistruct.__version__))


class GdataParser(KaitaiStruct):
    """Creator: Florian Bausch, ERNW Research GmbH, https://ernw-research.de
    License: CC-BY-SA-4.0 https://creativecommons.org/licenses/by-sa/4.0/
    """

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.magic1 = self._io.read_bytes(4)
        if not self.magic1 == b"\xCA\xFE\xBA\xBE":
            raise kaitaistruct.ValidationNotEqualError(
                b"\xCA\xFE\xBA\xBE", self.magic1, self._io, u"/seq/0")
        self.len_data1 = self._io.read_u4le()
        self._raw__raw_data1 = self._io.read_bytes(self.len_data1)
        _process = maldump.utils.CustomArc4(
            b"\xA7\xBF\x73\xA0\x9F\x03\xD3\x11\x85\x6F\x00\x80\xAD\xA9\x6E\x9B")
        self._raw_data1 = _process.decode(self._raw__raw_data1)
        _io__raw_data1 = KaitaiStream(BytesIO(self._raw_data1))
        self.data1 = GdataParser.EncryptedData1(
            _io__raw_data1, self, self._root)
        self.magic2 = self._io.read_bytes(4)
        if not self.magic2 == b"\xBA\xAD\xF0\x0D":
            raise kaitaistruct.ValidationNotEqualError(
                b"\xBA\xAD\xF0\x0D", self.magic2, self._io, u"/seq/3")
        self.len_data2 = self._io.read_u4le()
        self._raw__raw_data2 = self._io.read_bytes(self.len_data2)
        _process = maldump.utils.CustomArc4(
            b"\xA7\xBF\x73\xA0\x9F\x03\xD3\x11\x85\x6F\x00\x80\xAD\xA9\x6E\x9B")
        self._raw_data2 = _process.decode(self._raw__raw_data2)
        _io__raw_data2 = KaitaiStream(BytesIO(self._raw_data2))
        self.data2 = GdataParser.EncryptedData2(
            _io__raw_data2, self, self._root)
        self._raw_mal_file = self._io.read_bytes_full()
        _process = maldump.utils.CustomArc4(
            b"\xA7\xBF\x73\xA0\x9F\x03\xD3\x11\x85\x6F\x00\x80\xAD\xA9\x6E\x9B")
        self.mal_file = _process.decode(self._raw_mal_file)

    class EncryptedData1(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.unknown1 = self._io.read_u4le()
            self.unknown2 = self._io.read_u4le()
            self.unknown3 = self._io.read_u4le()
            self.quatime = self._io.read_u4le()
            self.unknown5 = self._io.read_u4le()
            self.malwaretype = GdataParser.Utf16le(self._io, self, self._root)

    class EncryptedData2(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.unknown1 = self._io.read_u4le()
            self.unknown2 = self._io.read_u4le()
            self.filesize = self._io.read_u4le()
            self.unknownstring1 = GdataParser.Utf16le(
                self._io, self, self._root)
            self.unknown4 = self._io.read_u4le()
            self.unkown5 = self._io.read_u4le()
            self.time1 = GdataParser.Winfiletime(self._io, self, self._root)
            self.time2 = GdataParser.Winfiletime(self._io, self, self._root)
            self.time3 = GdataParser.Winfiletime(self._io, self, self._root)
            self.unknown6 = self._io.read_u4le()
            self.filesize2 = self._io.read_u4le()
            self.path = GdataParser.Utf16le(self._io, self, self._root)

    class Utf16le(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.bom = self._io.read_bytes(3)
            if not self.bom == b"\xFF\xFE\xFF":
                raise kaitaistruct.ValidationNotEqualError(
                    b"\xFF\xFE\xFF", self.bom, self._io, u"/types/utf16le/seq/0")
            self.number_of_chars = self._io.read_u1()
            self.string_content = (self._io.read_bytes(
                (self.number_of_chars * 2))).decode(u"utf-16le")

    class Winfiletime(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.ts = self._io.read_u8le()

        @property
        def unixts(self):
            if hasattr(self, '_m_unixts'):
                return self._m_unixts

            self._m_unixts = ((self.ts * 1E-7) - 11644473600)
            return getattr(self, '_m_unixts', None)
