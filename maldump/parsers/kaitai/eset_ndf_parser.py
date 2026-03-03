# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
# type: ignore

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
import maldump.utils


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 11):
    raise Exception("Incompatible Kaitai Struct Python API: 0.11 or later is required, but you have %s" % (kaitaistruct.__version__))

class EsetNdfParser(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        super(EsetNdfParser, self).__init__(_io)
        self._parent = _parent
        self._root = _root or self
        self._read()

    def _read(self):
        self.magic = self._io.read_bytes(8)
        if not self.magic == b"\x46\x51\x44\x46\xA4\x0F\x00\x00":
            raise kaitaistruct.ValidationNotEqualError(b"\x46\x51\x44\x46\xA4\x0F\x00\x00", self.magic, self._io, u"/seq/0")
        self.num_findings = self._io.read_u4le()
        self.datetime_unix = EsetNdfParser.Unixdate(self._io, self, self._root)
        self.filler = self._io.read_bytes(4)
        if not self.filler == b"\x00\x00\x00\x00":
            raise kaitaistruct.ValidationNotEqualError(b"\x00\x00\x00\x00", self.filler, self._io, u"/seq/3")
        self.mal_size = self._io.read_u8le()
        self.len_mal_hash_sha1 = self._io.read_u4le()
        self.mal_hash_sha1 = self._io.read_bytes(self.len_mal_hash_sha1)
        self.findings = []
        for i in range(self.num_findings):
            self.findings.append(EsetNdfParser.Threat(self._io, self, self._root))



    def _fetch_instances(self):
        pass
        self.datetime_unix._fetch_instances()
        for i in range(len(self.findings)):
            pass
            self.findings[i]._fetch_instances()


    class Dateblock(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetNdfParser.Dateblock, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.date_block_size = self._io.read_u4le()
            if self.date_block_size != 0:
                pass
                self.date_block_contents = EsetNdfParser.DateblockContents(self._io, self, self._root)



        def _fetch_instances(self):
            pass
            if self.date_block_size != 0:
                pass
                self.date_block_contents._fetch_instances()



    class DateblockContents(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetNdfParser.DateblockContents, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.date_block_header = self._io.read_bytes(4)
            if not self.date_block_header == b"\x4E\x49\x57\x49":
                raise kaitaistruct.ValidationNotEqualError(b"\x4E\x49\x57\x49", self.date_block_header, self._io, u"/types/dateblock_contents/seq/0")
            self.datetime_quar_enc_start = EsetNdfParser.Windate(self._io, self, self._root)
            self.datetime_first_utc = EsetNdfParser.Windate(self._io, self, self._root)
            self.datetime_quar_enc_stop = EsetNdfParser.Windate(self._io, self, self._root)
            self.unknown_size = self._io.read_u4le()


        def _fetch_instances(self):
            pass
            self.datetime_quar_enc_start._fetch_instances()
            self.datetime_first_utc._fetch_instances()
            self.datetime_quar_enc_stop._fetch_instances()


    class Threat(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetNdfParser.Threat, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.mal_path = EsetNdfParser.Widestr(self._io, self, self._root)
            self.date_block = EsetNdfParser.Dateblock(self._io, self, self._root)
            self.datetime_latest_occurence = EsetNdfParser.Unixdate(self._io, self, self._root)
            self.filler1 = self._io.read_bytes(4)
            if not self.filler1 == b"\x00\x00\x00\x00":
                raise kaitaistruct.ValidationNotEqualError(b"\x00\x00\x00\x00", self.filler1, self._io, u"/types/threat/seq/3")
            self.threat_local = EsetNdfParser.Widestr(self._io, self, self._root)
            self.threat_canonized = EsetNdfParser.Widestr(self._io, self, self._root)
            self.filler2 = self._io.read_bytes(4)
            if not self.filler2 == b"\x00\x00\x00\x00":
                raise kaitaistruct.ValidationNotEqualError(b"\x00\x00\x00\x00", self.filler2, self._io, u"/types/threat/seq/6")
            self.threat_occurence = self._io.read_u4le()
            self.unknown = self._io.read_bytes(4)
            self.datetime_unix = EsetNdfParser.Unixdate(self._io, self, self._root)
            self.mal_path2 = EsetNdfParser.Widestr(self._io, self, self._root)


        def _fetch_instances(self):
            pass
            self.mal_path._fetch_instances()
            self.date_block._fetch_instances()
            self.datetime_latest_occurence._fetch_instances()
            self.threat_local._fetch_instances()
            self.threat_canonized._fetch_instances()
            self.datetime_unix._fetch_instances()
            self.mal_path2._fetch_instances()


    class Unixdate(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetNdfParser.Unixdate, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self._raw_date_time = self._io.read_bytes(4)
            _process = maldump.utils.RawTimeConverter(u"unix")
            self.date_time = _process.decode(self._raw_date_time)


        def _fetch_instances(self):
            pass


    class Widestr(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetNdfParser.Widestr, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.len_str = self._io.read_u4le()
            self.str = (self._io.read_bytes(2 * self.len_str)).decode(u"UTF-16LE")


        def _fetch_instances(self):
            pass


    class Windate(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(EsetNdfParser.Windate, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self._raw_date_time = self._io.read_bytes(8)
            _process = maldump.utils.RawTimeConverter(u"windows")
            self.date_time = _process.decode(self._raw_date_time)


        def _fetch_instances(self):
            pass



