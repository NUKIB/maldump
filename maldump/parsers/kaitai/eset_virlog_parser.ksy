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
      - id: unknown_u4int1
        type: u4
      - id: unknown_u4int2
        type: u4
      - id: unknown_u4int3
        type: u4

      - id: data_fields
        type: op
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
            'opcode::firstseen': unixdate
            'opcode::unknown_hash': hash
            'opcode::unknown_hash2': hash
            'opcode::unknown_hash3': hash
            'opcode::program_hash': hash
            'opcode::object_hash': hash
            'opcode::unknown_u1int1': u1
            'opcode::unknown_u1int2': u1
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
            'opcode::unknown_u4int16': u4
            'opcode::unknown_u8int1': u8
            'opcode::unknown_u8int2': u8
            'opcode::unknown_u8int3': u8
            'opcode::unknown_epilogue': epilogue

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

  epilogue:
    seq:
      - id: data
        size-eos: true

enums:
  opcode:
    0x4e2717:
      id: "virus_db"
      -orig-id: VIRUS_DB
    0x4e03ee:
      id: "user_name"
      -orig-id: USER_NAME
    0x4513ed:
      id: "unknown_u4int1"
      -orig-id: UNKNOWN_U4INT1
    0x4513ec:
      id: "unknown_u4int2"
      -orig-id: UNKNOWN_U4INT1
    0x463afc:
      id: "unknown_u8int1"
      -orig-id: UNKNOWN_U8INT1
    0x450bc2:
      id: "unknown_u4int3"
      -orig-id: UNKNOWN_U4INT3
    0x450bc1:
      id: "unknown_u4int4"
      -orig-id: UNKNOWN_U4INT4
    0x45139c:
      id: "unknown_u4int5"
      -orig-id: UNKNOWN_U4INT5
    0x4a13a8:
      id: "unknown_u8int2"
      -orig-id: UNKNOWN_U8INT2
    0x4e0bc4:
      id: "program_name"
      -orig-id: PROGRAM_NAME
    0x4e13a9:
      id: "path_name"
      -orig-id: PATH_NAME
    0x4e13a7:
      id: "progpath_name"
      -orig-id: PROGPATH_NAME
    0x46139f:
      id: "firstseen"
      -orig-id: FIRSTSEEN
    0x4213a0:
      id: "unknown_hash"
      -orig-id: UNKNOWN_HASH
    0x4213a4:
      id: "unknown_hash2"
      -orig-id: UNKNOWN_HASH2
    0x4213ab:
      id: "unknown_hash3"
      -orig-id: UNKNOWN_HASH3
    0x450fa0:
      id: "unknown_u4int6"
      -orig-id: UNKNOWN_U4INT6
    0x4513aa:
      id: "unknown_u4int7"
      -orig-id: UNKNOWN_U4INT7
    0x460fab:
      id: "unknown_u8int3"
      -orig-id: UNKNOWN_U8INT3
    0x42139d:
      id: "program_hash"
      -orig-id: PROGRAM_HASH
    0x42139e:
      id: "object_hash"
      -orig-id: OBJECT_HASH
    0x4e0bbe:
      id: "object_name"
      -orig-id: OBJECT_NAME
    0x431d77:
      id: "unknown_u1int1"
      -orig-id: UNKNOWN_U1INT1
    0x4e1d4d:
      id: "infiltration_name"
      -orig-id: INFILTRATION_NAME
    0x431d4f:
      id: "unknown_u1int2"
      -orig-id: UNKNOWN_U1INT2
    0x451389:
      id: "unknown_u4int8"
      -orig-id: UNKNOWN_U4INT8
    0x4532c8:
      id: "unknown_u4int9"
      -orig-id: UNKNOWN_U4INT9
    0x4503ea:
      id: "unknown_u4int10"
      -orig-id: UNKNOWN_U4INT10
    0x450bc0:
      id: "unknown_u4int11"
      -orig-id: UNKNOWN_U4INT11
    0x450bbf:
      id: "unknown_u4int12"
      -orig-id: UNKNOWN_U4INT12
    0x450bba:
      id: "unknown_u4int13"
      -orig-id: UNKNOWN_U4INT13
    0x410004:
      id: "unknown_u4int14"
      -orig-id: UNKNOWN_U4INT14
    0x410005:
      id: "unknown_u4int15"
      -orig-id: UNKNOWN_U4INT15
    0x41000a:
      id: "unknown_u4int16"
      -orig-id: UNKNOWN_U4INT16
    0x450bc3:
      id: "unknown_epilogue"
      -orig-id: UNKNOWN_EPILOGUE
