# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
import maldump.utils


if getattr(kaitaistruct, "API_VERSION", (0, 9)) < (0, 9):
    raise Exception(
        "Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s"
        % (kaitaistruct.__version__)
    )


class EsetNdfParser(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.magic = self._io.read_bytes(8)
        if not self.magic == b"\x46\x51\x44\x46\xa4\x0f\x00\x00":
            raise kaitaistruct.ValidationNotEqualError(
                b"\x46\x51\x44\x46\xa4\x0f\x00\x00", self.magic, self._io, "/seq/0"
            )
        self.num_findings = self._io.read_u4le()
        self.datetime_unix = EsetNdfParser.Unixdate(self._io, self, self._root)
        self.filler = self._io.read_bytes(4)
        if not self.filler == b"\x00\x00\x00\x00":
            raise kaitaistruct.ValidationNotEqualError(
                b"\x00\x00\x00\x00", self.filler, self._io, "/seq/3"
            )
        self.mal_size = self._io.read_u8le()
        self.len_mal_hash_sha1 = self._io.read_u4le()
        self.mal_hash_sha1 = self._io.read_bytes(self.len_mal_hash_sha1)
        self.findings = []
        for i in range(self.num_findings):
            self.findings.append(EsetNdfParser.Threat(self._io, self, self._root))

    class Threat(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.mal_path = EsetNdfParser.Widestr(self._io, self, self._root)
            self.date_block_size = self._io.read_u4le()
            self.date_block_header = self._io.read_bytes(4)
            if not self.date_block_header == b"\x4e\x49\x57\x49":
                raise kaitaistruct.ValidationNotEqualError(
                    b"\x4e\x49\x57\x49",
                    self.date_block_header,
                    self._io,
                    "/types/threat/seq/2",
                )
            self.datetime_quar_enc_start = EsetNdfParser.Windate(
                self._io, self, self._root
            )
            self.datetime_first_utc = EsetNdfParser.Windate(self._io, self, self._root)
            self.datetime_quar_enc_stop = EsetNdfParser.Windate(
                self._io, self, self._root
            )
            self.unknown_size = self._io.read_u4le()
            self.datetime_latest_occurence = EsetNdfParser.Unixdate(
                self._io, self, self._root
            )
            self.filler1 = self._io.read_bytes(4)
            if not self.filler1 == b"\x00\x00\x00\x00":
                raise kaitaistruct.ValidationNotEqualError(
                    b"\x00\x00\x00\x00", self.filler1, self._io, "/types/threat/seq/8"
                )
            self.threat_local = EsetNdfParser.Widestr(self._io, self, self._root)
            self.threat_canonized = EsetNdfParser.Widestr(self._io, self, self._root)
            self.filler2 = self._io.read_bytes(4)
            if not self.filler2 == b"\x00\x00\x00\x00":
                raise kaitaistruct.ValidationNotEqualError(
                    b"\x00\x00\x00\x00", self.filler2, self._io, "/types/threat/seq/11"
                )
            self.threat_occurence = self._io.read_u4le()
            self.unknown = self._io.read_bytes(4)
            self.datetime_unix = EsetNdfParser.Unixdate(self._io, self, self._root)
            self.mal_path2 = EsetNdfParser.Widestr(self._io, self, self._root)

    class Windate(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self._raw_date_time = self._io.read_bytes(8)
            _process = maldump.utils.RawTimeConverter("windows")
            self.date_time = _process.decode(self._raw_date_time)

    class Unixdate(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self._raw_date_time = self._io.read_bytes(4)
            _process = maldump.utils.RawTimeConverter("unix")
            self.date_time = _process.decode(self._raw_date_time)

    class Widestr(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.str_len = self._io.read_u4le()
            self.str_cont = (self._io.read_bytes((2 * self.str_len))).decode("UTF-16LE")
