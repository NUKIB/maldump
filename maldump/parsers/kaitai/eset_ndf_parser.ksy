meta:
  id: eset_ndf_parser
  title: ESET Antivirus quarantine metadata file parser (NDF)
  file-extension: NDF
  endian: le
seq:
  - id: magic
    size: 0x08
    contents: [ 0x46, 0x51, 0x44, 0x46, 0xa4, 0x0f, 0x00, 0x00 ]  # FQDF
  - id: num_findings
    type: u4
  - id: datetime_unix
    type: unixdate
  - id: filler
    size: 0x04
    contents: [ 0x00, 0x00, 0x00, 0x00 ]
  - id: mal_size
    type: u8
  - id: len_mal_hash_sha1
    type: u4
  - id: mal_hash_sha1
    size: len_mal_hash_sha1
  - id: findings
    type: threat
    repeat-expr: num_findings
    repeat: expr


types:
  threat:
    seq:
      - id: mal_path
        type: widestr
      - id: date_block_size
        type: u4
      - id: date_block_header
        size: 0x04
        contents: [ 0x4e, 0x49, 0x57, 0x49 ]  # NIWI
      - id: datetime_quar_enc_start
        type: windate
      - id: datetime_first_utc
        type: windate
      - id: datetime_quar_enc_stop
        type: windate
      - id: unknown_size
        type: u4
      - id: datetime_latest_occurence
        type: unixdate
      - id: filler1
        size: 0x04
        contents: [ 0x00, 0x00, 0x00, 0x00 ]
      - id: threat_local
        type: widestr
      - id: threat_canonized
        type: widestr
      - id: filler2
        size: 0x04
        contents: [ 0x00, 0x00, 0x00, 0x00 ]
      - id: threat_occurence
        type: u4
      - id: unknown
        size: 0x04
      - id: datetime_unix
        type: unixdate
      - id: mal_path2
        type: widestr

  windate:
    seq:
      - id: date_time
        size: 0x08
        process: maldump.utils.raw_time_converter( "windows" )
  unixdate:
    seq:
      - id: date_time
        size: 0x04
        process: maldump.utils.raw_time_converter( "unix" )

  widestr:
    seq:
      - id: len_str
        type: u4
      - id: str
        type: str
        encoding: UTF-16LE
        size: 2 * len_str
