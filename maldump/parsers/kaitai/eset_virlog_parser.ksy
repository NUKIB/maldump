meta:
  id: eset_virlog_parser
  title: ESET Antivirus quarantine file parser (virlog.dat)
  file-extension: dat
  endian: le
seq:
  - id: magic
    size: 0x04
    contents: [ 0x78, 0xf3, 0x9b, 0xcf ]
  - id: len_header
    type: u4
  - id: header
    type: header
    size: len_header - 0x08

  - id: threats
    type: threat
    repeat-expr: header.num_threats
    repeat: expr

types:
  header:
    seq:
      - id: num_threats
        type: u4
      - id: filesize
        type: u8
      - id: timsestamp
        type: windate
      - id: windowsdatetime_unknown2
        type: windate
      - id: windowsdatetime_unknown3
        type: windate
      - id: num_threats2
        type: u4
        valid:
          expr: _ == num_threats
      - id: unknown
        size-eos: true

  threat:
    seq:
      - id: magic
        contents: [ 0xdc, 0xcf, 0x8b, 0x63 ]
      - id: len_record
        type: u4
      - id: record
        type: record
        size: len_record - 0x8

  subsubrecord:
    seq:
      - id: data_fields
        type: op
        repeat: eos

  subrecord:
    seq:
      - id: unknown_u4int1
        type: u4
      - id: unknown_u4int2
        type: u4
      - id: len_subsubrecords
        type: u4

      - id: subsubrecords
        type: subsubrecord
        size: len_subsubrecords

  record:
    seq:
      - id: record_header_magic
        size: 0x08
        contents: [ 0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00 ]
      - id: record_id
        type: u4
      - id: win_timestamp
        type: windate
      - id: unknown_u4int0
        type: u4
      - id: record_id2   # this should be equal to record_id
        valid:
          expr: _ == record_id
        type: u4

      - id: subrecords
        type: subrecord
        repeat: eos
  op:
    seq:
      - id: name
        type: u4
        enum: opcode
      - id: arg
        type:
          switch-on: name
          cases:
            'opcode::virus_db': widestr
            'opcode::user_name': widestr
            'opcode::path_name': widestr
            'opcode::program_name': widestr
            'opcode::object_name': widestr
            'opcode::infiltration_name': widestr
            'opcode::progpath_name': widestr
            'opcode::win_product_name': widestr
            'opcode::win_exe_name': widestr
            'opcode::win_legal_copyright': widestr
            'opcode::win_product_name2': widestr
            'opcode::win_file_version': widestr
            'opcode::win_product_name3': widestr
            'opcode::win_company_name': widestr
            'opcode::unknown_string8': widestr
            'opcode::win_signing_cert': widestr
            'opcode::win_product_version': widestr
            'opcode::win_user_sid': widestr
            'opcode::execution_mode': widestr
            'opcode::source_web': cstr
            'opcode::firstseen': unixdate
            'opcode::unknown_date': windate
            'opcode::unknown_hash': hash
            'opcode::object_hash3': hash
            'opcode::unknown_hash3': hash
            'opcode::program_hash': hash
            'opcode::object_hash': hash
            'opcode::win_signing_cert_pubkey_fingerprint_hash': hash
            'opcode::object_hash2': hash
            'opcode::unknown_hash6': hash
            'opcode::unknown_u1int1': u1
            'opcode::unknown_u1int2': u1
            'opcode::unknown_u1int3': u1
            'opcode::unknown_u4int1': u4
            'opcode::unknown_u4int2': u4
            'opcode::unknown_u4int3': u4
            'opcode::unknown_u4int4': u4
            'opcode::unknown_u4int5': u4
            'opcode::unknown_u4int6': u4
            'opcode::unknown_u4int7': u4
            'opcode::unknown_u4int8': u4
            'opcode::unknown_u4int9': u4
            'opcode::unknown_u4int10': u4
            'opcode::unknown_u4int11': u4
            'opcode::unknown_u4int12': u4
            'opcode::unknown_u4int13': u4
            'opcode::unknown_u4int14': u4
            'opcode::unknown_u4int15': u4
            'opcode::unknown_u4int16': varlen
            'opcode::win_lang_id': u4
            'opcode::win_signing_cert_pubkey_params': u4
            'opcode::unknown_u4int19': u4
            'opcode::unknown_u4int20': u4
            'opcode::unknown_u4int21': u4
            'opcode::unknown_u4int22': s4le
            'opcode::unknown_u4int23': s4le
            'opcode::unknown_u4int24': u4
            'opcode::unknown_u4int25': u4
            'opcode::unknown_u4int26': u4
            'opcode::unknown_u8int27': u8
            'opcode::unknown_u4int28': u4
            'opcode::unknown_u4int29': u4
            'opcode::unknown_u4int30': u4
            'opcode::unknown_u8int1': u8
            'opcode::unknown_u8int2': weirddate
            'opcode::unknown_u8int3': u8
  varlen:
    seq:
      - id: len_str
        size: 4

  widestr:
    seq:
      - id: len_str
        type: u4
      - id: str
        type: str
        encoding: UTF-16LE
        size: len_str - 2
      - id: nullbytes
        contents: [ 0x00, 0x00 ]
        if: len_str != 0

  cstr:  # C-like string
    seq:
      - id: len_str
        type: u4
      - id: str
        type: str
        encoding: UTF-8
        size: len_str - 1
      - id: nullbytes
        contents: [ 0x00 ]
        if: len_str != 0

  hash:
    seq:
      - id: len_hash
        type: u4
      - id: hash
        size: len_hash
  windate:
    seq:
      - id: date_time
        size: 0x08
        process: maldump.utils.raw_time_converter( "windows" )

  unixdate:
    seq:
      - id: date_time
        size: 0x08
        process: maldump.utils.raw_time_converter( "unix" )

  weirddate:
    seq:
      - id: unknown_num
        type: u4
      - id: date_time
        size: 0x04
        process: maldump.utils.raw_time_converter( "unix" )

  epilogue:
    seq:
      - id: data
        size-eos: true

enums:
  opcode:
    # probably splitters
    0x410003:
      id: "unknown_u4int23"
      -orig-id: UNKNOWN_U4INT23
    0x410004:
      id: "unknown_u4int14"
      -orig-id: UNKNOWN_U4INT14
    0x410005:
      id: "unknown_u4int15"
      -orig-id: UNKNOWN_U4INT15
    0x410006:
      id: "unknown_u4int22"
      -orig-id: UNKNOWN_U4INT22
    0x410009:
      id: "unknown_u4int26"
      -orig-id: UNKNOWN_U4INT26
    0x41000a:
      id: "unknown_u4int16"
      -orig-id: UNKNOWN_U4INT16

    # HASHes
    0x42139e:
      id: "object_hash"
      -orig-id: OBJECT_HASH
    0x42139d:
      id: "program_hash"
      -orig-id: PROGRAM_HASH
    0x4213a0:
      id: "unknown_hash"
      -orig-id: UNKNOWN_HASH
    0x4213a4:
      id: "object_hash3"
      -orig-id: OBJECT_HASH3
    0x4213ab:
      id: "unknown_hash3"
      -orig-id: UNKNOWN_HASH3
    0x4213ad:
      id: "unknown_hash6"
      -orig-id: UNKNOWN_HASH6
    0x4213ae:
      id: "object_hash2"
      -orig-id: OBJECT_HASH2
    0x4213b3:
      id: "win_signing_cert_pubkey_fingerprint_hash"
      -orig-id: WIN_SIGN_CERT_PUBKEY_FINGERPTINT_HASH

    # U1 data types
    0x431b60:
      id: "unknown_u1int3"
      -orig-id: UNKNOWN_U1INT3
    0x431d4f:
      id: "unknown_u1int2"
      -orig-id: UNKNOWN_U1INT2
    0x431d77:
      id: "unknown_u1int1"
      -orig-id: UNKNOWN_U1INT1

    # U4 data type
    0x450001:
      id: "unknown_u4int19"
      -orig-id: UNKNOWN_U4INT19
    0x4503ea:
      id: "unknown_u4int10"
      -orig-id: UNKNOWN_U4INT10
    0x4507d0:
      id: "unknown_u4int24"
      -orig-id: UNKNOWN_U4INT24
    0x450bba:
      id: "unknown_u4int13"
      -orig-id: UNKNOWN_U4INT13
    0x450bbf:
      id: "unknown_u4int12"
      -orig-id: UNKNOWN_U4INT12
    0x450bc0:
      id: "unknown_u4int11"
      -orig-id: UNKNOWN_U4INT11
    0x450bc1:
      id: "unknown_u4int4"
      -orig-id: UNKNOWN_U4INT4
    0x450bc2:
      id: "unknown_u4int3"
      -orig-id: UNKNOWN_U4INT3
    0x450bc3:
      id: "unknown_u4int21"
      -orig-id: UNKNOWN_U4INT21
    0x450fa0:
      id: "unknown_u4int6"
      -orig-id: UNKNOWN_U4INT6
    0x451389:
      id: "unknown_u4int8"
      -orig-id: UNKNOWN_U4INT8
    0x45138a:
      id: "unknown_u4int25"
      -orig-id: UNKNOWN_U4INT25
    0x45139c:
      id: "unknown_u4int5"
      -orig-id: UNKNOWN_U4INT5
    0x4513aa:
      id: "unknown_u4int7"
      -orig-id: UNKNOWN_U4INT7
    0x4513b0:
      id: "unknown_u4int20"
      -orig-id: UNKNOWN_U4INT20
    0x4513b2:
      id: "win_signing_cert_pubkey_params"
      -orig-id: WIN_SIGN_CERT_PUBKEY_PARAMS
    0x4513ec:
      id: "unknown_u4int2"
      -orig-id: UNKNOWN_U4INT1
    0x4513ed:
      id: "unknown_u4int1"
      -orig-id: UNKNOWN_U4INT1
    0x452787:
      id: "win_lang_id"
      -orig-id: WIN_LANG_ID
    0x4532c8:
      id: "unknown_u4int9"
      -orig-id: UNKNOWN_U4INT9
    0x451b68:
      id: "unknown_u4int29"
      -orig-id: UNKNOWN_U4INT29
    0x451f4b:
      id: "unknown_u4int30"
      -orig-id: UNKNOWN_U4INT30
    0x452790:
      id: "unknown_u4int28"
      -orig-id: UNKNOWN_U4INT28

    # U8 data types / DATES
    0x460fab:
      id: "unknown_u8int3"
      -orig-id: UNKNOWN_U8INT3
    0x46139f:
      id: "firstseen"
      -orig-id: FIRSTSEEN
    0x4613b1:
      id: "unknown_date"
      -orig-id: UNKNOWN_DATE
    0x462791:
      id: "unknown_u8int27"
      -orig-id: UNKNOWN_U8INT27
    0x463afc:
      id: "unknown_u8int1"
      -orig-id: UNKNOWN_U8INT1

    # C-like string
    0x4d2792:
      id: "source_web"
      -orig-id: SOURCE_WEB

    # unknown
    0x4a13a8:
      id: "unknown_u8int2"
      -orig-id: UNKNOWN_U8INT2

    # wide strings
    0x4e03ee:
      id: "user_name"
      -orig-id: USER_NAME
    0x4e03f5:
      id: "win_user_sid"
      -orig-id: WIN_USER_SID
    0x4e0bbe:
      id: "object_name"
      -orig-id: OBJECT_NAME
    0x4e0bc4:
      id: "program_name"
      -orig-id: PROGRAM_NAME
    0x4e13a7:
      id: "progpath_name"
      -orig-id: PROGPATH_NAME
    0x4e13a9:
      id: "path_name"
      -orig-id: PATH_NAME
    0x4e13b4:
      id: "win_signing_cert"
      -orig-id: WIN_SIGNING_CERT
    0x4e1b59:
      id: "execution_mode"
      -orig-id: EXECUTION_MODE
    0x4e1d4d:
      id: "infiltration_name"
      -orig-id: INFILTRATION_NAME
    0x4e2717:
      id: "virus_db"
      -orig-id: VIRUS_DB
    0x4e2786:
      id: "unknown_string8"
      -orig-id: UNKNOWN_STRING8
    0x4e2788:
      id: "win_company_name"
      -orig-id: WIN_COMPANY_NAME
    0x4e2789:
      id: "win_product_name3"
      -orig-id: WIN_PRODUCT_NAME3
    0x4e278a:
      id: "win_file_version"
      -orig-id: WIN_FILE_VERSION
    0x4e278b:
      id: "win_product_name2"
      -orig-id: WIN_PRODUCT_NAME2
    0x4e278c:
      id: "win_legal_copyright"
      -orig-id: WIN_LEGAL_COYRIGHT
    0x4e278d:
      id: "win_exe_name"
      -orig-id: WIN_EXE_NAME
    0x4e278e:
      id: "win_product_name"
      -orig-id: WIN_PRODUCT_NAME
    0x4e278f:
      id: "win_product_version"
      -orig-id: WIN_PRODUCT_VERSION
