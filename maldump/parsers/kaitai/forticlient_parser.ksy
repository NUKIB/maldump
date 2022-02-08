meta:
  id: forticlient_parser
  endian: le
  title: FortiClient quarantine file parser
  license: CC-BY-SA-4.0
  ks-version: 0.9
doc: |
  Creator: Nikola Knezevic
  License: CC-BY-SA-4.0 https://creativecommons.org/licenses/by-sa/4.0/
seq:
  - id: magic
    size: 8
    contents: ["QUARF", 0x00, 0x00, 0x00]
  - id: unknown1
    type: u4
  - id: mal_offset
    type: u4
  - id: unknown2
    size: 36
  - id: mal_len
    type: u4
  - id: timestamp
    type: timestamp
    size: 16
  - id: unknown3
    size: 0xC
  - id: file_id
    type: u4
  - id: len_mal_path
    type: u4
  - id: len_mal_type
    type: u4
  - id: mal_path
    type: str
    encoding: UTF-16LE
    size: len_mal_path
  - id: mal_type
    type: str
    encoding: UTF-16LE
    size: len_mal_type
  - id: mal_file
    process: xor(0xab)
    size-eos: true
types:
  timestamp:
    seq:
      - id: year
        type: u2
      - id: month
        type: u2
      - id: tz_offset
        type: u2
      - id: day
        type: u2
      - id: hour
        type: u2
      - id: minute
        type: u2
      - id: second
        type: u2
      - id: microsecond
        type: u2