meta:
  id: yaffs
  endian: le
  encoding: ASCII
  title: Yaffs header
doc: |
    Yealink partial yaffs header
    (c) Synacktiv 2019

seq:
  - id: obj_type
    type: u4
    enum: obj_type
  - id: parent_obj_id
    type: u4
  - id: unused_checksum
    contents: [0xFF, 0xFF]
  - id: name
    type: strz
    size: 256
  - id: yst_mode
    type: u4
  - id: yst_uid
    type: u4
  - id: yst_gid
    type: u4
  - id: yst_atime
    type: u4
  - id: yst_mtime
    type: u4
  - id: yst_ctime
    type: u4
  - id: padding
    type: u2
  - id: file_size_low
    type: u4
  - id: equiv_id
    type: u4
  - id: alias
    type:
        switch-on: obj_type
        cases:
            'obj_type::symlink': strz
            _ : u1

    size: 128
enums:
  obj_type:
    0x00: unknown
    0x01: file
    0x02: symlink
    0x03: directory
    0x04: hardlink
    0x05: special
