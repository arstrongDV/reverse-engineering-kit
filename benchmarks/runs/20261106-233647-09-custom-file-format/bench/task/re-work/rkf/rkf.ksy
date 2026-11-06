meta:
  id: rkf
  title: RKF container (alpha/bravo/charlie samples)
  file-extension: rkf
  endian: le
  encoding: UTF-8
doc: |
  Magic "RKF1", u2 version, u2 record count,
  then `count` records, then a u4 CRC-32 (zlib) of all preceding bytes.
  Record: u1 type, u2 len, body. Types: 1 = string (UTF-8), 2 = s4 (len is 4), 3 = raw bytes.
  Versions 2 and 3 were seen with identical layout.
seq:
  - id: magic
    contents: "RKF1"
  - id: version
    type: u2
  - id: num_records
    type: u2
  - id: records
    type: record
    repeat: expr
    repeat-expr: num_records
  - id: crc32
    type: u4
types:
  record:
    seq:
      - id: type
        type: u1
        enum: rec_type
      - id: len_body
        type: u2
      - id: body
        size: len_body
        type:
          switch-on: type
          cases:
            'rec_type::string': str_body
            'rec_type::int32': int_body
  str_body:
    seq:
      - id: value
        type: str
        size-eos: true
  int_body:
    seq:
      - id: value
        type: s4
enums:
  rec_type:
    1: string
    2: int32
    3: bytes
