meta:
  id: yealinkrom
  endian: be
  encoding: ASCII
  title: Yealink ROM update format

doc: |
    Yealink phones ROM updates
    Both the ROM and the blocks have a similar header,
    but the blocks can be encrypted
    (c) Synacktiv 2019

seq:
  - id: header
    size: 0x80
    type: rom_header
  - id: rawdata
    size-eos: true
    if: header.common_header.crypto_type != 0
  - id: blocks
    type: block
    repeat: expr
    repeat-expr: header.rom_blocks
    if: header.common_header.crypto_type == 0

types:
  rom_header:
    seq:
      - id: magic
        contents: [0xAD, 0x24, 0xEC, 0x0B]
      - id: common_header
        type: common_header
      - id: rom_verify
        type: u4
      - id: rom_blocks
        type: u4
      - id: rom_dev_id
        type: u4
      - id: rom_dev_name
        type: strz
        size: 16
      - id: rom_oem_name
        type: strz
        size: 16
      - id: rom_version
        type: strz
        size: 16
      - id: unknown_buffer
        size: 8
      - id: rom_hw_id
        type: u4
      - id: rom_sw_id
        type: u4
      - id: rom_rom_cid_array
        size: 16
      - id: unknown_buffer_3
        size: 12
  block:
    seq:
      - id: hdr
        size: 0x80
        type: block_header
      - id: data
        size: hdr.block_total - hdr.common_header.header_size
  raw_data:
    seq:
      - id: data
        size-eos: true
  block_header:
    seq:
      - id: magic
        contents: [0xEB, 0x9F, 0x56, 0xC9]
      - id: common_header
        type: common_header
      - id: block_total
        type: u4
      - id: verify
        type: u4
      - id: block_type
        type: u4
        enum: block_type
      - id: blk_id
        type: u4
      - id: blk_name
        type: strz
        size: 16
      - id: blk_version
        size: 16
      - id: unknown_buffer
        size: 8
      - id: cipher
        type: u4
      - id: raw_or_file
        type: u4
      - id: unknown_buffer2
        size: 40
  common_header:
    seq:
      - id: header_size
        type: u4
      - id: header_crc
        type: u4
      - id: crypto_type
        type: u1
      - id: header_unknownflag
        type: u1
      - id: header_format
        type: u2
      - id: header_flags
        type: u4
      - id: length
        type: u4
enums:
  block_type:
    0x00: none
    0x01: bin
    0x02: tool
    0x03: file
    0x04: nand_raw
    0x05: nand_oob
    0x06: nor_raw
    0x07: script
    0x08: execute
    0x09: emmc_raw
    0x0A: unknown
