# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
# type: ignore

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import IntEnum
import maldump.utils


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 11):
    raise Exception("Incompatible Kaitai Struct Python API: 0.11 or later is required, but you have %s" % (kaitaistruct.__version__))

class EsetVirlogParser(KaitaiStruct):

    class Opcode(IntEnum):
        unknown_u4int14 = 4259844
        unknown_u4int15 = 4259845
        unknown_u4int16 = 4259850
        program_hash = 4330397
        object_hash = 4330398
        unknown_hash = 4330400
        unknown_hash2 = 4330404
        unknown_hash3 = 4330411
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
        super(EsetVirlogParser, self).__init__(_io)
        self._parent = _parent
        self._root = _root or self
        self._read()

    def _read(self):
        self.magic = self._io.read_bytes(4)
        if not self.magic == b"\x78\xF3\x9B\xCF":
            raise kaitaistruct.ValidationNotEqualError(b"\x78\xF3\x9B\xCF", self.magic, self._io, u"/seq/0")
        self.len_header = self._io.read_u4le()
        self._raw_header = self._io.read_bytes(self.len_header - 8)
        _io__raw_header = KaitaiStream(BytesIO(self._raw_header))
        self.header = EsetVirlogParser.Header(_io__raw_header, self, self._root)
        self.threats = []
        for i in range(self.header.num_threats):
            self.threats.append(EsetVirlogParser.Threat(self._io, self, self._root))



    def _fetch_instances(self):
        pass
        self.header._fetch_instances()
        for i in range(len(self.threats)):
            pass
            self.threats[i]._fetch_instances()


    class Epilogue(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetVirlogParser.Epilogue, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.data = self._io.read_bytes_full()


        def _fetch_instances(self):
            pass


    class Hash(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetVirlogParser.Hash, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.len_hash = self._io.read_u4le()
            self.hash = self._io.read_bytes(self.len_hash)


        def _fetch_instances(self):
            pass


    class Header(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetVirlogParser.Header, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.num_threats = self._io.read_u4le()
            self.filesize = self._io.read_u8le()
            self.timsestamp = EsetVirlogParser.Windate(self._io, self, self._root)
            self.windowsdatetime_unknown2 = EsetVirlogParser.Windate(self._io, self, self._root)
            self.windowsdatetime_unknown3 = EsetVirlogParser.Windate(self._io, self, self._root)
            self.num_threats2 = self._io.read_u4le()
            self.unknown = self._io.read_bytes_full()


        def _fetch_instances(self):
            pass
            self.timsestamp._fetch_instances()
            self.windowsdatetime_unknown2._fetch_instances()
            self.windowsdatetime_unknown3._fetch_instances()


    class Op(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetVirlogParser.Op, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.name = KaitaiStream.resolve_enum(EsetVirlogParser.Opcode, self._io.read_u4le())
            _on = self.name
            if _on == EsetVirlogParser.Opcode.firstseen:
                pass
                self.arg = EsetVirlogParser.Unixdate(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.infiltration_name:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.object_hash:
                pass
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.object_name:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.path_name:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.progpath_name:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.program_hash:
                pass
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.program_name:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_epilogue:
                pass
                self.arg = EsetVirlogParser.Epilogue(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_hash:
                pass
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_hash2:
                pass
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_hash3:
                pass
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_u1int1:
                pass
                self.arg = self._io.read_u1()
            elif _on == EsetVirlogParser.Opcode.unknown_u1int2:
                pass
                self.arg = self._io.read_u1()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int1:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int10:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int11:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int12:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int13:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int14:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int15:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int16:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int2:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int3:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int4:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int5:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int6:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int7:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int8:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int9:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u8int1:
                pass
                self.arg = self._io.read_u8le()
            elif _on == EsetVirlogParser.Opcode.unknown_u8int2:
                pass
                self.arg = self._io.read_u8le()
            elif _on == EsetVirlogParser.Opcode.unknown_u8int3:
                pass
                self.arg = self._io.read_u8le()
            elif _on == EsetVirlogParser.Opcode.user_name:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.virus_db:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)


        def _fetch_instances(self):
            pass
            _on = self.name
            if _on == EsetVirlogParser.Opcode.firstseen:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.infiltration_name:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.object_hash:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.object_name:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.path_name:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.progpath_name:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.program_hash:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.program_name:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.unknown_epilogue:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.unknown_hash:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.unknown_hash2:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.unknown_hash3:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.unknown_u1int1:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u1int2:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int1:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int10:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int11:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int12:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int13:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int14:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int15:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int16:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int2:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int3:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int4:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int5:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int6:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int7:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int8:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int9:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u8int1:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u8int2:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u8int3:
                pass
            elif _on == EsetVirlogParser.Opcode.user_name:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.virus_db:
                pass
                self.arg._fetch_instances()


    class Record(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetVirlogParser.Record, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.record_header_magic = self._io.read_bytes(8)
            if not self.record_header_magic == b"\x24\x00\x00\x00\x01\x00\x01\x00":
                raise kaitaistruct.ValidationNotEqualError(b"\x24\x00\x00\x00\x01\x00\x01\x00", self.record_header_magic, self._io, u"/types/record/seq/0")
            self.record_id = self._io.read_u4le()
            self.win_timestamp = EsetVirlogParser.Windate(self._io, self, self._root)
            self.unknown_u4int0 = self._io.read_u4le()
            self.record_id2 = self._io.read_u4le()
            self.unknown_u4int1 = self._io.read_u4le()
            self.unknown_u4int2 = self._io.read_u4le()
            self.unknown_u4int3 = self._io.read_u4le()
            self.data_fields = []
            i = 0
            while not self._io.is_eof():
                self.data_fields.append(EsetVirlogParser.Op(self._io, self, self._root))
                i += 1



        def _fetch_instances(self):
            pass
            self.win_timestamp._fetch_instances()
            for i in range(len(self.data_fields)):
                pass
                self.data_fields[i]._fetch_instances()



    class Threat(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetVirlogParser.Threat, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(4)
            if not self.magic == b"\xDC\xCF\x8B\x63":
                raise kaitaistruct.ValidationNotEqualError(b"\xDC\xCF\x8B\x63", self.magic, self._io, u"/types/threat/seq/0")
            self.len_record = self._io.read_u4le()
            self._raw_record = self._io.read_bytes(self.len_record - 8)
            _io__raw_record = KaitaiStream(BytesIO(self._raw_record))
            self.record = EsetVirlogParser.Record(_io__raw_record, self, self._root)


        def _fetch_instances(self):
            pass
            self.record._fetch_instances()


    class Unixdate(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetVirlogParser.Unixdate, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self._raw_date_time = self._io.read_bytes(8)
            _process = maldump.utils.RawTimeConverter(u"unix")
            self.date_time = _process.decode(self._raw_date_time)


        def _fetch_instances(self):
            pass


    class Widestr(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetVirlogParser.Widestr, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.len_str = self._io.read_u4le()
            self.str = (self._io.read_bytes(self.len_str - 2)).decode(u"UTF-16LE")
            if self.len_str != 0:
                pass
                self.nullbytes = self._io.read_bytes(2)
                if not self.nullbytes == b"\x00\x00":
                    raise kaitaistruct.ValidationNotEqualError(b"\x00\x00", self.nullbytes, self._io, u"/types/widestr/seq/2")



        def _fetch_instances(self):
            pass
            if self.len_str != 0:
                pass



    class Windate(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetVirlogParser.Windate, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self._raw_date_time = self._io.read_bytes(8)
            _process = maldump.utils.RawTimeConverter(u"windows")
            self.date_time = _process.decode(self._raw_date_time)


        def _fetch_instances(self):
            pass



