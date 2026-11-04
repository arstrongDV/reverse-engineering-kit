meta:
  id: rkf
  file-extension: rkf
  endian: le
seq:
  - id: magic
    contents: RKF1
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
      - id: kind
        type: u1
        enum: record_kind
      - id: length
        type: u2
      - id: value
        size: length
        type:
          switch-on: kind
          cases:
            record_kind::text: text_value
            record_kind::number: number_value
  text_value:
    seq:
      - id: text
        type: str
        size-eos: true
        encoding: UTF-8
  number_value:
    seq:
      - id: number
        type: s4
enums:
  record_kind:
    1: text
    2: number
    3: blob
