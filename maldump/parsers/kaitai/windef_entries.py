# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from enum import Enum

import kaitaistruct
from kaitaistruct import BytesIO, KaitaiStream, KaitaiStruct

import maldump.utils

if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (
        kaitaistruct.__version__))


class WindefEntries(KaitaiStruct):
    """Creator: Florian Bausch, ERNW Research GmbH, https://ernw-research.de
    License: CC-BY-SA-4.0 https://creativecommons.org/licenses/by-sa/4.0/
    Modified: Nikola Knežević
    """

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self._raw__raw_header = self._io.read_bytes(60)
        _process = maldump.utils.CustomArc4(b"\x1E\x87\x78\x1B\x8D\xBA\xA8\x44\xCE\x69\x70\x2C\x0C\x78\xB7\x86\xA3\xF6\x23\xB7\x38\xF5\xED\xF9\xAF\x83\x53\x0F\xB3\xFC\x54\xFA\xA2\x1E\xB9\xCF\x13\x31\xFD\x0F\x0D\xA9\x54\xF6\x87\xCB\x9E\x18\x27\x96\x97\x90\x0E\x53\xFB\x31\x7C\x9C\xBC\xE4\x8E\x23\xD0\x53\x71\xEC\xC1\x59\x51\xB8\xF3\x64\x9D\x7C\xA3\x3E\xD6\x8D\xC9\x04\x7E\x82\xC9\xBA\xAD\x97\x99\xD0\xD4\x58\xCB\x84\x7C\xA9\xFF\xBE\x3C\x8A\x77\x52\x33\x55\x7D\xDE\x13\xA8\xB1\x40\x87\xCC\x1B\xC8\xF1\x0F\x6E\xCD\xD0\x83\xA9\x59\xCF\xF8\x4A\x9D\x1D\x50\x75\x5E\x3E\x19\x18\x18\xAF\x23\xE2\x29\x35\x58\x76\x6D\x2C\x07\xE2\x57\x12\xB2\xCA\x0B\x53\x5E\xD8\xF6\xC5\x6C\xE7\x3D\x24\xBD\xD0\x29\x17\x71\x86\x1A\x54\xB4\xC2\x85\xA9\xA3\xDB\x7A\xCA\x6D\x22\x4A\xEA\xCD\x62\x1D\xB9\xF2\xA2\x2E\xD1\xE9\xE1\x1D\x75\xBE\xD7\xDC\x0E\xCB\x0A\x8E\x68\xA2\xFF\x12\x63\x40\x8D\xC8\x08\xDF\xFD\x16\x4B\x11\x67\x74\xCD\x0B\x9B\x8D\x05\x41\x1E\xD6\x26\x2E\x42\x9B\xA4\x95\x67\x6B\x83\x98\xDB\x2F\x35\xD3\xC1\xB9\xCE\xD5\x26\x36\xF2\x76\x5E\x1A\x95\xCB\x7C\xA4\xC3\xDD\xAB\xDD\xBF\xF3\x82\x53")
        self._raw_header = _process.decode(self._raw__raw_header)
        _io__raw_header = KaitaiStream(BytesIO(self._raw_header))
        self.header = WindefEntries.Rc4encryptedHeader(
            _io__raw_header, self, self._root)
        self._raw__raw_data1 = self._io.read_bytes(self.header.len1)
        _process = maldump.utils.CustomArc4(b"\x1E\x87\x78\x1B\x8D\xBA\xA8\x44\xCE\x69\x70\x2C\x0C\x78\xB7\x86\xA3\xF6\x23\xB7\x38\xF5\xED\xF9\xAF\x83\x53\x0F\xB3\xFC\x54\xFA\xA2\x1E\xB9\xCF\x13\x31\xFD\x0F\x0D\xA9\x54\xF6\x87\xCB\x9E\x18\x27\x96\x97\x90\x0E\x53\xFB\x31\x7C\x9C\xBC\xE4\x8E\x23\xD0\x53\x71\xEC\xC1\x59\x51\xB8\xF3\x64\x9D\x7C\xA3\x3E\xD6\x8D\xC9\x04\x7E\x82\xC9\xBA\xAD\x97\x99\xD0\xD4\x58\xCB\x84\x7C\xA9\xFF\xBE\x3C\x8A\x77\x52\x33\x55\x7D\xDE\x13\xA8\xB1\x40\x87\xCC\x1B\xC8\xF1\x0F\x6E\xCD\xD0\x83\xA9\x59\xCF\xF8\x4A\x9D\x1D\x50\x75\x5E\x3E\x19\x18\x18\xAF\x23\xE2\x29\x35\x58\x76\x6D\x2C\x07\xE2\x57\x12\xB2\xCA\x0B\x53\x5E\xD8\xF6\xC5\x6C\xE7\x3D\x24\xBD\xD0\x29\x17\x71\x86\x1A\x54\xB4\xC2\x85\xA9\xA3\xDB\x7A\xCA\x6D\x22\x4A\xEA\xCD\x62\x1D\xB9\xF2\xA2\x2E\xD1\xE9\xE1\x1D\x75\xBE\xD7\xDC\x0E\xCB\x0A\x8E\x68\xA2\xFF\x12\x63\x40\x8D\xC8\x08\xDF\xFD\x16\x4B\x11\x67\x74\xCD\x0B\x9B\x8D\x05\x41\x1E\xD6\x26\x2E\x42\x9B\xA4\x95\x67\x6B\x83\x98\xDB\x2F\x35\xD3\xC1\xB9\xCE\xD5\x26\x36\xF2\x76\x5E\x1A\x95\xCB\x7C\xA4\xC3\xDD\xAB\xDD\xBF\xF3\x82\x53")
        self._raw_data1 = _process.decode(self._raw__raw_data1)
        _io__raw_data1 = KaitaiStream(BytesIO(self._raw_data1))
        self.data1 = WindefEntries.EncryptedData1(
            _io__raw_data1, self, self._root)
        self._raw__raw_data2 = self._io.read_bytes(self.header.len2)
        _process = maldump.utils.CustomArc4(b"\x1E\x87\x78\x1B\x8D\xBA\xA8\x44\xCE\x69\x70\x2C\x0C\x78\xB7\x86\xA3\xF6\x23\xB7\x38\xF5\xED\xF9\xAF\x83\x53\x0F\xB3\xFC\x54\xFA\xA2\x1E\xB9\xCF\x13\x31\xFD\x0F\x0D\xA9\x54\xF6\x87\xCB\x9E\x18\x27\x96\x97\x90\x0E\x53\xFB\x31\x7C\x9C\xBC\xE4\x8E\x23\xD0\x53\x71\xEC\xC1\x59\x51\xB8\xF3\x64\x9D\x7C\xA3\x3E\xD6\x8D\xC9\x04\x7E\x82\xC9\xBA\xAD\x97\x99\xD0\xD4\x58\xCB\x84\x7C\xA9\xFF\xBE\x3C\x8A\x77\x52\x33\x55\x7D\xDE\x13\xA8\xB1\x40\x87\xCC\x1B\xC8\xF1\x0F\x6E\xCD\xD0\x83\xA9\x59\xCF\xF8\x4A\x9D\x1D\x50\x75\x5E\x3E\x19\x18\x18\xAF\x23\xE2\x29\x35\x58\x76\x6D\x2C\x07\xE2\x57\x12\xB2\xCA\x0B\x53\x5E\xD8\xF6\xC5\x6C\xE7\x3D\x24\xBD\xD0\x29\x17\x71\x86\x1A\x54\xB4\xC2\x85\xA9\xA3\xDB\x7A\xCA\x6D\x22\x4A\xEA\xCD\x62\x1D\xB9\xF2\xA2\x2E\xD1\xE9\xE1\x1D\x75\xBE\xD7\xDC\x0E\xCB\x0A\x8E\x68\xA2\xFF\x12\x63\x40\x8D\xC8\x08\xDF\xFD\x16\x4B\x11\x67\x74\xCD\x0B\x9B\x8D\x05\x41\x1E\xD6\x26\x2E\x42\x9B\xA4\x95\x67\x6B\x83\x98\xDB\x2F\x35\xD3\xC1\xB9\xCE\xD5\x26\x36\xF2\x76\x5E\x1A\x95\xCB\x7C\xA4\xC3\xDD\xAB\xDD\xBF\xF3\x82\x53")
        self._raw_data2 = _process.decode(self._raw__raw_data2)
        _io__raw_data2 = KaitaiStream(BytesIO(self._raw_data2))
        self.data2 = WindefEntries.EncryptedData2(
            _io__raw_data2, self, self._root)

    class EncryptedData2(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.number_of_entries = self._io.read_u4le()
            self.offset = []
            for i in range(self.number_of_entries):
                self.offset.append(self._io.read_u4le())

        class Entrys(KaitaiStruct):
            def __init__(self, i, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self.i = i
                self._read()

            def _read(self):
                self._raw_entry = self._io.read_bytes(
                    (self._parent.offset[(self.i + 1)] - self._parent.offset[self.i]))
                _io__raw_entry = KaitaiStream(BytesIO(self._raw_entry))
                self.entry = WindefEntries.Entry(
                    _io__raw_entry, self, self._root)

        class Entrye(KaitaiStruct):
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):
                self.entry = WindefEntries.Entry(self._io, self, self._root)

        @property
        def entries(self):
            if hasattr(self, '_m_entries'):
                return self._m_entries

            _pos = self._io.pos()
            self._io.seek(self.offset[0])
            self._m_entries = []
            for i in range(self.number_of_entries):
                _on = i != (self.number_of_entries - 1)
                if _on == True:
                    self._m_entries.append(WindefEntries.EncryptedData2.Entrys(
                        i, self._io, self, self._root))
                elif _on == False:
                    self._m_entries.append(
                        WindefEntries.EncryptedData2.Entrye(self._io, self, self._root))

            self._io.seek(_pos)
            return getattr(self, '_m_entries', None)

    class Guid(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.id1 = self._io.read_u4le()
            self.id2 = self._io.read_u2le()
            self.id3 = self._io.read_u2le()
            self.id4 = self._io.read_bytes(2)
            self.id5 = self._io.read_bytes(6)

    class Entry(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.path = WindefEntries.NullTerminatedUtf16le(
                self._io, self, self._root)
            self.number_of_elements = self._io.read_u2le()
            self.typestr = (self._io.read_bytes_term(
                0, False, True, True)).decode(u"UTF8")
            self.padding = self._io.read_bytes(((4 - self._io.pos()) % 4))
            self.element = []
            for i in range(self.number_of_elements):
                self.element.append(WindefEntries.Listelement(
                    self._io, self, self._root))

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

    class EncryptedData1(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.guid = WindefEntries.Guid(self._io, self, self._root)
            self.unknown3 = self._io.read_bytes(16)
            self.time = WindefEntries.Winfiletime(self._io, self, self._root)
            self.id11 = self._io.read_u4le()
            self.id12 = self._io.read_u2le()
            self.id13 = self._io.read_u2le()
            self.number_of_strings = self._io.read_u4le()
            self.mal_type = (self._io.read_bytes_term(
                0, False, True, True)).decode(u"UTF-8")

    class StrUtf16le(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.value = (self._io.read_bytes_full()).decode(u"UTF-16LE")

    class NullTerminatedUtf16le(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.character = []
            i = 0
            while True:
                _ = self._io.read_u2le()
                self.character.append(_)
                if self.character[i] == 0:
                    break
                i += 1

    class Hash(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.value = self._io.read_bytes(20)

    class Listelement(KaitaiStruct):

        class Elementtypes(Enum):
            utf16 = 32
            uint4 = 48
            hash = 64
            winfiletime = 96

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.length = self._io.read_u2le()
            self.elementsubtype = self._io.read_u1()
            self.elementtype = KaitaiStream.resolve_enum(
                WindefEntries.Listelement.Elementtypes, self._io.read_u1())
            _on = self.elementtype
            if _on == WindefEntries.Listelement.Elementtypes.winfiletime:
                self._raw_content = self._io.read_bytes(self.length)
                _io__raw_content = KaitaiStream(BytesIO(self._raw_content))
                self.content = WindefEntries.Winfiletime(
                    _io__raw_content, self, self._root)
            elif _on == WindefEntries.Listelement.Elementtypes.utf16:
                self._raw_content = self._io.read_bytes(self.length)
                _io__raw_content = KaitaiStream(BytesIO(self._raw_content))
                self.content = WindefEntries.StrUtf16le(
                    _io__raw_content, self, self._root)
            elif _on == WindefEntries.Listelement.Elementtypes.hash:
                self._raw_content = self._io.read_bytes(self.length)
                _io__raw_content = KaitaiStream(BytesIO(self._raw_content))
                self.content = WindefEntries.Hash(
                    _io__raw_content, self, self._root)
            elif _on == WindefEntries.Listelement.Elementtypes.uint4:
                self.content = self._io.read_u4le()
            else:
                self.content = self._io.read_bytes(self.length)
            self.padding = self._io.read_bytes(((4 - self._io.pos()) % 4))

    class Rc4encryptedHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(16)
            if not self.magic == b"\xDB\xE8\xC5\x01\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00":
                raise kaitaistruct.ValidationNotEqualError(
                    b"\xDB\xE8\xC5\x01\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00", self.magic, self._io, u"/types/rc4encrypted_header/seq/0")
            self.unknown1 = self._io.read_bytes(24)
            self.len1 = self._io.read_u4le()
            self.len2 = self._io.read_u4le()
            self.unknown2 = self._io.read_bytes(12)
