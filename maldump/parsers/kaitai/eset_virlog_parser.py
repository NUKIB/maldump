# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import maldump.utils


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class EsetVirlogParser(KaitaiStruct):

    class Opcode(Enum):
        unknown_u4int14 = 4259844
        unknown_u4int15 = 4259845
        unknown_u4int16 = 4259850
        program_hash = 4330397
        object_hash = 4330398
        unknown_hash = 4330400
        unknown_hash2 = 4330404
        unknown_u1int2 = 4398415
        unknown_u1int1 = 4398455
        unknown_u4int10 = 4522986
        unknown_u4int13 = 4524986
        unknown_u4int12 = 4524991
        unknown_u4int11 = 4524992
        unknown_u4int4 = 4524993
        unknown_u4int3 = 4524994
        unknown_epilogue = 4524995
        unknown_u4int6 = 4525984
        unknown_u4int8 = 4526985
        unknown_u4int5 = 4527004
        unknown_u4int7 = 4527018
        unknown_u4int2 = 4527084
        unknown_u4int1 = 4527085
        unknown_u4int9 = 4534984
        unknown_u8int3 = 4591531
        firstseen = 4592543
        unknown_u8int1 = 4602620
        unknown_u8int2 = 4854696
        user_name = 5112814
        object_name = 5114814
        program_name = 5114820
        progpath_name = 5116839
        path_name = 5116841
        infiltration_name = 5119309
        virus_db = 5121815
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.magic = self._io.read_bytes(4)
        if not self.magic == b"\x78\xF3\x9B\xCF":
            raise kaitaistruct.ValidationNotEqualError(b"\x78\xF3\x9B\xCF", self.magic, self._io, u"/seq/0")
        self.len_header = self._io.read_u4le()
        self._raw_header = self._io.read_bytes((self.len_header - 8))
        _io__raw_header = KaitaiStream(BytesIO(self._raw_header))
        self.header = EsetVirlogParser.Header(_io__raw_header, self, self._root)
        self.threats = []
        for i in range(self.header.num_threats):
            self.threats.append(EsetVirlogParser.Threat(self._io, self, self._root))


    class Widestr(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.len_str = self._io.read_u4le()
            self.str = (self._io.read_bytes((self.len_str - 2))).decode(u"UTF-16LE")
            if self.len_str != 0:
                self.nullbytes = self._io.read_bytes(2)
                if not self.nullbytes == b"\x00\x00":
                    raise kaitaistruct.ValidationNotEqualError(b"\x00\x00", self.nullbytes, self._io, u"/types/widestr/seq/2")



    class Unixdate(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self._raw_date_time = self._io.read_bytes(8)
            _process = maldump.utils.RawTimeConverter(u"unix")
            self.date_time = _process.decode(self._raw_date_time)


    class Hash(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.len_hash = self._io.read_u4le()
            self.hash = self._io.read_bytes(self.len_hash)


    class Header(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.num_threats = self._io.read_u4le()
            self.filesize = self._io.read_u8le()
            self.timsestamp = EsetVirlogParser.Windate(self._io, self, self._root)
            self.windowsdatetime_unknown2 = EsetVirlogParser.Windate(self._io, self, self._root)
            self.windowsdatetime_unknown3 = EsetVirlogParser.Windate(self._io, self, self._root)
            self.num_threats2 = self._io.read_u4le()
            _ = self.num_threats2
            if not _ == self.num_threats:
                raise kaitaistruct.ValidationExprError(self.num_threats2, self._io, u"/types/header/seq/5")
            self.unknown = self._io.read_bytes_full()


    class Threat(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(4)
            if not self.magic == b"\xDC\xCF\x8B\x63":
                raise kaitaistruct.ValidationNotEqualError(b"\xDC\xCF\x8B\x63", self.magic, self._io, u"/types/threat/seq/0")
            self.len_record = self._io.read_u4le()
            self._raw_record = self._io.read_bytes((self.len_record - 8))
            _io__raw_record = KaitaiStream(BytesIO(self._raw_record))
            self.record = EsetVirlogParser.Record(_io__raw_record, self, self._root)


    class Epilogue(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = self._io.read_bytes_full()


    class Record(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.record_header_magic = self._io.read_bytes(8)
            if not self.record_header_magic == b"\x24\x00\x00\x00\x01\x00\x01\x00":
                raise kaitaistruct.ValidationNotEqualError(b"\x24\x00\x00\x00\x01\x00\x01\x00", self.record_header_magic, self._io, u"/types/record/seq/0")
            self.record_id = self._io.read_u4le()
            self.win_timestamp = EsetVirlogParser.Windate(self._io, self, self._root)
            self.filler = self._io.read_bytes(4)
            if not self.filler == b"\x00\x00\x00\x00":
                raise kaitaistruct.ValidationNotEqualError(b"\x00\x00\x00\x00", self.filler, self._io, u"/types/record/seq/3")
            self.record_id2 = self._io.read_u4le()
            _ = self.record_id2
            if not _ == self.record_id:
                raise kaitaistruct.ValidationExprError(self.record_id2, self._io, u"/types/record/seq/4")
            self.unknown_u4int1 = self._io.read_u4le()
            self.unknown_u4int2 = self._io.read_u4le()
            self.unknown_u4int3 = self._io.read_u4le()
            self.data_fields = []
            i = 0
            while not self._io.is_eof():
                self.data_fields.append(EsetVirlogParser.Op(self._io, self, self._root))
                i += 1



    class Windate(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self._raw_date_time = self._io.read_bytes(8)
            _process = maldump.utils.RawTimeConverter(u"windows")
            self.date_time = _process.decode(self._raw_date_time)


    class Op(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.name = KaitaiStream.resolve_enum(EsetVirlogParser.Opcode, self._io.read_u4le())
            _on = self.name
            if _on == EsetVirlogParser.Opcode.unknown_u1int1:
                self.arg = self._io.read_u1()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int7:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int8:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int16:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_hash:
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_u4int15:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int3:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int1:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u1int2:
                self.arg = self._io.read_u1()
            elif _on == EsetVirlogParser.Opcode.path_name:
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.program_hash:
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.firstseen:
                self.arg = EsetVirlogParser.Unixdate(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_u4int2:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.progpath_name:
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.infiltration_name:
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_hash2:
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_u4int14:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_epilogue:
                self.arg = EsetVirlogParser.Epilogue(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.program_name:
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.object_name:
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_u8int1:
                self.arg = self._io.read_u8le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int13:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int4:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u8int3:
                self.arg = self._io.read_u8le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int5:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.virus_db:
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.object_hash:
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_u4int12:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u8int2:
                self.arg = self._io.read_u8le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int9:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int10:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int6:
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.user_name:
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_u4int11:
                self.arg = self._io.read_u4le()



