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
        unknown_u4int23 = 4259843
        unknown_u4int14 = 4259844
        unknown_u4int15 = 4259845
        unknown_u4int22 = 4259846
        unknown_u4int26 = 4259849
        unknown_u4int16 = 4259850
        program_hash = 4330397
        object_hash = 4330398
        unknown_hash = 4330400
        object_hash3 = 4330404
        unknown_hash3 = 4330411
        unknown_hash6 = 4330413
        object_hash2 = 4330414
        win_signing_cert_pubkey_fingerprint_hash = 4330419
        unknown_u1int3 = 4397920
        unknown_u1int2 = 4398415
        unknown_u1int1 = 4398455
        unknown_u4int19 = 4521985
        unknown_u4int10 = 4522986
        unknown_u4int24 = 4523984
        unknown_u4int13 = 4524986
        unknown_u4int12 = 4524991
        unknown_u4int11 = 4524992
        unknown_u4int4 = 4524993
        unknown_u4int3 = 4524994
        unknown_u4int21 = 4524995
        unknown_u4int6 = 4525984
        unknown_u4int8 = 4526985
        unknown_u4int25 = 4526986
        unknown_u4int5 = 4527004
        unknown_u4int7 = 4527018
        unknown_u4int20 = 4527024
        win_signing_cert_pubkey_params = 4527026
        unknown_u4int2 = 4527084
        unknown_u4int1 = 4527085
        unknown_u4int29 = 4529000
        unknown_u4int30 = 4529995
        win_lang_id = 4532103
        unknown_u4int28 = 4532112
        unknown_u4int9 = 4534984
        unknown_u8int3 = 4591531
        firstseen = 4592543
        unknown_date = 4592561
        unknown_u8int27 = 4597649
        unknown_u8int1 = 4602620
        unknown_u8int2 = 4854696
        source_web = 5056402
        user_name = 5112814
        win_user_sid = 5112821
        object_name = 5114814
        program_name = 5114820
        progpath_name = 5116839
        path_name = 5116841
        win_signing_cert = 5116852
        execution_mode = 5118809
        infiltration_name = 5119309
        virus_db = 5121815
        unknown_string8 = 5121926
        win_company_name = 5121928
        win_product_name3 = 5121929
        win_file_version = 5121930
        win_product_name2 = 5121931
        win_legal_copyright = 5121932
        win_exe_name = 5121933
        win_product_name = 5121934
        win_product_version = 5121935
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


    class Cstr(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetVirlogParser.Cstr, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.len_str = self._io.read_u4le()
            self.str = (self._io.read_bytes(self.len_str - 1)).decode(u"UTF-8")
            if self.len_str != 0:
                pass
                self.nullbytes = self._io.read_bytes(1)
                if not self.nullbytes == b"\x00":
                    raise kaitaistruct.ValidationNotEqualError(b"\x00", self.nullbytes, self._io, u"/types/cstr/seq/2")



        def _fetch_instances(self):
            pass
            if self.len_str != 0:
                pass



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
            _ = self.num_threats2
            if not _ == self.num_threats:
                raise kaitaistruct.ValidationExprError(self.num_threats2, self._io, u"/types/header/seq/5")
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
            if _on == EsetVirlogParser.Opcode.execution_mode:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.firstseen:
                pass
                self.arg = EsetVirlogParser.Unixdate(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.infiltration_name:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.object_hash:
                pass
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.object_hash2:
                pass
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.object_hash3:
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
            elif _on == EsetVirlogParser.Opcode.source_web:
                pass
                self.arg = EsetVirlogParser.Cstr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_date:
                pass
                self.arg = EsetVirlogParser.Windate(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_hash:
                pass
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_hash3:
                pass
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_hash6:
                pass
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_string8:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_u1int1:
                pass
                self.arg = self._io.read_u1()
            elif _on == EsetVirlogParser.Opcode.unknown_u1int2:
                pass
                self.arg = self._io.read_u1()
            elif _on == EsetVirlogParser.Opcode.unknown_u1int3:
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
                self.arg = EsetVirlogParser.Varlen(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_u4int19:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int2:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int20:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int21:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int22:
                pass
                self.arg = self._io.read_s4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int23:
                pass
                self.arg = self._io.read_s4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int24:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int25:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int26:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int28:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int29:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int3:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int30:
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
                self.arg = EsetVirlogParser.Weirddate(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.unknown_u8int27:
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
            elif _on == EsetVirlogParser.Opcode.win_company_name:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.win_exe_name:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.win_file_version:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.win_lang_id:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.win_legal_copyright:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.win_product_name:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.win_product_name2:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.win_product_name3:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.win_product_version:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.win_signing_cert:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.win_signing_cert_pubkey_fingerprint_hash:
                pass
                self.arg = EsetVirlogParser.Hash(self._io, self, self._root)
            elif _on == EsetVirlogParser.Opcode.win_signing_cert_pubkey_params:
                pass
                self.arg = self._io.read_u4le()
            elif _on == EsetVirlogParser.Opcode.win_user_sid:
                pass
                self.arg = EsetVirlogParser.Widestr(self._io, self, self._root)


        def _fetch_instances(self):
            pass
            _on = self.name
            if _on == EsetVirlogParser.Opcode.execution_mode:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.firstseen:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.infiltration_name:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.object_hash:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.object_hash2:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.object_hash3:
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
            elif _on == EsetVirlogParser.Opcode.source_web:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.unknown_date:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.unknown_hash:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.unknown_hash3:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.unknown_hash6:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.unknown_string8:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.unknown_u1int1:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u1int2:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u1int3:
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
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.unknown_u4int19:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int2:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int20:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int21:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int22:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int23:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int24:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int25:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int26:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int28:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int29:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int3:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u4int30:
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
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.unknown_u8int27:
                pass
            elif _on == EsetVirlogParser.Opcode.unknown_u8int3:
                pass
            elif _on == EsetVirlogParser.Opcode.user_name:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.virus_db:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.win_company_name:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.win_exe_name:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.win_file_version:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.win_lang_id:
                pass
            elif _on == EsetVirlogParser.Opcode.win_legal_copyright:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.win_product_name:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.win_product_name2:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.win_product_name3:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.win_product_version:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.win_signing_cert:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.win_signing_cert_pubkey_fingerprint_hash:
                pass
                self.arg._fetch_instances()
            elif _on == EsetVirlogParser.Opcode.win_signing_cert_pubkey_params:
                pass
            elif _on == EsetVirlogParser.Opcode.win_user_sid:
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
            _ = self.record_id2
            if not _ == self.record_id:
                raise kaitaistruct.ValidationExprError(self.record_id2, self._io, u"/types/record/seq/4")
            self.subrecords = []
            i = 0
            while not self._io.is_eof():
                self.subrecords.append(EsetVirlogParser.Subrecord(self._io, self, self._root))
                i += 1



        def _fetch_instances(self):
            pass
            self.win_timestamp._fetch_instances()
            for i in range(len(self.subrecords)):
                pass
                self.subrecords[i]._fetch_instances()



    class Subrecord(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetVirlogParser.Subrecord, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.unknown_u4int1 = self._io.read_u4le()
            self.unknown_u4int2 = self._io.read_u4le()
            self.len_subsubrecords = self._io.read_u4le()
            self._raw_subsubrecords = self._io.read_bytes(self.len_subsubrecords)
            _io__raw_subsubrecords = KaitaiStream(BytesIO(self._raw_subsubrecords))
            self.subsubrecords = EsetVirlogParser.Subsubrecord(_io__raw_subsubrecords, self, self._root)


        def _fetch_instances(self):
            pass
            self.subsubrecords._fetch_instances()


    class Subsubrecord(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetVirlogParser.Subsubrecord, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.data_fields = []
            i = 0
            while not self._io.is_eof():
                self.data_fields.append(EsetVirlogParser.Op(self._io, self, self._root))
                i += 1



        def _fetch_instances(self):
            pass
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


    class Varlen(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetVirlogParser.Varlen, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.len_str = self._io.read_bytes(4)


        def _fetch_instances(self):
            pass


    class Weirddate(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetVirlogParser.Weirddate, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.unknown_num = self._io.read_u4le()
            self._raw_date_time = self._io.read_bytes(4)
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



