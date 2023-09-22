# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import BytesIO, KaitaiStream, KaitaiStruct

import maldump.utils

if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (
        kaitaistruct.__version__))


class WindefResourceData(KaitaiStruct):
    """Creator: Florian Bausch, ERNW Research GmbH, https://ernw-research.de
    Edited: 
    License: CC-BY-SA-4.0 https://creativecommons.org/licenses/by-sa/4.0/
    """

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self._raw__raw_encryptedfile = self._io.read_bytes_full()
        _process = maldump.utils.CustomArc4(b"\x1E\x87\x78\x1B\x8D\xBA\xA8\x44\xCE\x69\x70\x2C\x0C\x78\xB7\x86\xA3\xF6\x23\xB7\x38\xF5\xED\xF9\xAF\x83\x53\x0F\xB3\xFC\x54\xFA\xA2\x1E\xB9\xCF\x13\x31\xFD\x0F\x0D\xA9\x54\xF6\x87\xCB\x9E\x18\x27\x96\x97\x90\x0E\x53\xFB\x31\x7C\x9C\xBC\xE4\x8E\x23\xD0\x53\x71\xEC\xC1\x59\x51\xB8\xF3\x64\x9D\x7C\xA3\x3E\xD6\x8D\xC9\x04\x7E\x82\xC9\xBA\xAD\x97\x99\xD0\xD4\x58\xCB\x84\x7C\xA9\xFF\xBE\x3C\x8A\x77\x52\x33\x55\x7D\xDE\x13\xA8\xB1\x40\x87\xCC\x1B\xC8\xF1\x0F\x6E\xCD\xD0\x83\xA9\x59\xCF\xF8\x4A\x9D\x1D\x50\x75\x5E\x3E\x19\x18\x18\xAF\x23\xE2\x29\x35\x58\x76\x6D\x2C\x07\xE2\x57\x12\xB2\xCA\x0B\x53\x5E\xD8\xF6\xC5\x6C\xE7\x3D\x24\xBD\xD0\x29\x17\x71\x86\x1A\x54\xB4\xC2\x85\xA9\xA3\xDB\x7A\xCA\x6D\x22\x4A\xEA\xCD\x62\x1D\xB9\xF2\xA2\x2E\xD1\xE9\xE1\x1D\x75\xBE\xD7\xDC\x0E\xCB\x0A\x8E\x68\xA2\xFF\x12\x63\x40\x8D\xC8\x08\xDF\xFD\x16\x4B\x11\x67\x74\xCD\x0B\x9B\x8D\x05\x41\x1E\xD6\x26\x2E\x42\x9B\xA4\x95\x67\x6B\x83\x98\xDB\x2F\x35\xD3\xC1\xB9\xCE\xD5\x26\x36\xF2\x76\x5E\x1A\x95\xCB\x7C\xA4\xC3\xDD\xAB\xDD\xBF\xF3\x82\x53")
        self._raw_encryptedfile = _process.decode(self._raw__raw_encryptedfile)
        _io__raw_encryptedfile = KaitaiStream(BytesIO(self._raw_encryptedfile))
        self.encryptedfile = WindefResourceData.Rc4encrypted(
            _io__raw_encryptedfile, self, self._root)

    class Rc4encrypted(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.fixed = self._io.read_bytes(8)
            if not self.fixed == b"\x03\x00\x00\x00\x02\x00\x00\x00":
                raise kaitaistruct.ValidationNotEqualError(
                    b"\x03\x00\x00\x00\x02\x00\x00\x00", self.fixed, self._io, u"/types/rc4encrypted/seq/0")
            self.length = self._io.read_u4le()
            self.padding = self._io.read_bytes(8)
            self._raw_binarysd = self._io.read_bytes(self.length)
            _io__raw_binarysd = KaitaiStream(BytesIO(self._raw_binarysd))
            self.binarysd = WindefResourceData.Binarysd(
                _io__raw_binarysd, self, self._root)
            self.unknown1 = self._io.read_bytes(8)
            self.len_malfile = self._io.read_u8le()
            self.unknown2 = self._io.read_bytes(4)
            self.mal_file = self._io.read_bytes(self.len_malfile)

    class Binarysd(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.revision = self._io.read_u1()
            self.reserved = self._io.read_bytes(1)
            if not self.reserved == b"\x00":
                raise kaitaistruct.ValidationNotEqualError(
                    b"\x00", self.reserved, self._io, u"/types/binarysd/seq/1")
            self.control_flags = self._io.read_u2le()
            self.owner_offset = self._io.read_u4le()
            self.group_offset = self._io.read_u4le()
            self.sacl_offset = self._io.read_u4le()
            self.dacl_offset = self._io.read_u4le()

        @property
        def owner(self):
            if hasattr(self, '_m_owner'):
                return self._m_owner

            if self.owner_offset > 0:
                _pos = self._io.pos()
                self._io.seek(self.owner_offset)
                self._m_owner = WindefResourceData.Sid(
                    self._io, self, self._root)
                self._io.seek(_pos)

            return getattr(self, '_m_owner', None)

        @property
        def group(self):
            if hasattr(self, '_m_group'):
                return self._m_group

            if self.group_offset > 0:
                _pos = self._io.pos()
                self._io.seek(self.group_offset)
                self._m_group = WindefResourceData.Sid(
                    self._io, self, self._root)
                self._io.seek(_pos)

            return getattr(self, '_m_group', None)

        @property
        def dacl(self):
            if hasattr(self, '_m_dacl'):
                return self._m_dacl

            if self.dacl_offset > 0:
                _pos = self._io.pos()
                self._io.seek(self.dacl_offset)
                self._m_dacl = WindefResourceData.Acl(
                    self._io, self, self._root)
                self._io.seek(_pos)

            return getattr(self, '_m_dacl', None)

        @property
        def sacl(self):
            if hasattr(self, '_m_sacl'):
                return self._m_sacl

            if self.sacl_offset > 0:
                _pos = self._io.pos()
                self._io.seek(self.sacl_offset)
                self._m_sacl = WindefResourceData.Acl(
                    self._io, self, self._root)
                self._io.seek(_pos)

            return getattr(self, '_m_sacl', None)

    class Ace(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.accessallowtype = self._io.read_u1()
            self.flags = self._io.read_u1()
            self.acesize = self._io.read_u2le()
            self.accessmask = self._io.read_u4le()
            self._raw_sid = self._io.read_bytes((self.acesize - 8))
            _io__raw_sid = KaitaiStream(BytesIO(self._raw_sid))
            self.sid = WindefResourceData.Sid(_io__raw_sid, self, self._root)

    class Acl(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.revision = self._io.read_u1()
            self.reserved = self._io.read_bytes(1)
            if not self.reserved == b"\x00":
                raise kaitaistruct.ValidationNotEqualError(
                    b"\x00", self.reserved, self._io, u"/types/acl/seq/1")
            self.aclsize = self._io.read_u2le()
            self.acecount = self._io.read_u2le()
            self.reserved2 = self._io.read_bytes(2)
            if not self.reserved2 == b"\x00\x00":
                raise kaitaistruct.ValidationNotEqualError(
                    b"\x00\x00", self.reserved2, self._io, u"/types/acl/seq/4")
            self._raw_acelist = self._io.read_bytes((self.aclsize - 8))
            _io__raw_acelist = KaitaiStream(BytesIO(self._raw_acelist))
            self.acelist = WindefResourceData.Acelist(
                _io__raw_acelist, self, self._root)

    class Sid(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.revision = self._io.read_u1()
            self.number_of_chunks = self._io.read_u1()
            self.reserved = self._io.read_bytes(2)
            if not self.reserved == b"\x00\x00":
                raise kaitaistruct.ValidationNotEqualError(
                    b"\x00\x00", self.reserved, self._io, u"/types/sid/seq/2")
            self.firstchunk = self._io.read_u4be()
            self.chunk = []
            for i in range(self.number_of_chunks):
                self.chunk.append(self._io.read_u4le())

    class Acelist(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.ace = []
            i = 0
            while not self._io.is_eof():
                self.ace.append(WindefResourceData.Ace(
                    self._io, self, self._root))
                i += 1
