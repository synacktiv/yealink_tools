# coding: utf8
#!/usr/bin/env python3
"""
    Yealink update file parser
    Copyright 2019 Synacktiv

    Usage: compile the KSY file with kaitai-struct-compiler and then use
    this script to parse / dump the yealink firmware update file

    Licensed under the "THE BEER-WARE LICENSE" (Revision 42):
    Tristan P. wrote this file. As long as you retain this notice you
    can do whatever you want with this stuff. If we meet some day, and you think
    this stuff is worth it, you can buy me a beer or coffee in return

"""

import argparse
import struct
import logging
import lzma

from binascii import hexlify
from tqdm import tqdm

import yealinkrom
from yealink_crypto import get_crypto, decrypt_data


def get_block_type(block_type):
    """
        Wrapper to return the string corresponding to a block type
    """
    types = {
        yealinkrom.Yealinkrom.BlockType.none: "none",
        yealinkrom.Yealinkrom.BlockType.bin: "bin",
        yealinkrom.Yealinkrom.BlockType.tool: "tool",
        yealinkrom.Yealinkrom.BlockType.file: "file",
        yealinkrom.Yealinkrom.BlockType.nand_raw: "raw nand",
        yealinkrom.Yealinkrom.BlockType.nand_oob: "raw oob",
        yealinkrom.Yealinkrom.BlockType.nand_oob: "raw oob",
        yealinkrom.Yealinkrom.BlockType.nor_raw: "raw nor",
        yealinkrom.Yealinkrom.BlockType.script: "script",
        yealinkrom.Yealinkrom.BlockType.execute: "execute",
    }
    try:
        return types[block_type]
    except KeyError:
        return "unknown"

def decrypt_block(mupdate, data):
    """
        Decrypt a block according to it's crypto type
        Example: kernel.bin is almost always encrypted with cypher3
    """

    cypher = mupdate.header.common_header.crypto_type
    block_header = decrypt_data(data[:0x80], cypher)
    header_size = struct.unpack(">I", block_header[0x4:0x8])[0]
    block_total = struct.unpack(">I", block_header[24:28])[0]

    output = block_header
    logging.debug("Header size 0x%x", header_size)
    logging.debug("block  size 0x%x", block_total)


    if len(data) == block_total:
        logging.debug("Decrypting last block")
        output += decrypt_data(data[header_size:], cypher)
    elif decrypt_data(data[block_total-header_size:block_total],
                      cypher).startswith(b"\xeb\x9f\x56\xc9"):
        output += decrypt_data(data[header_size:block_total-header_size], cypher)
        logging.debug("decrypt with header")
    elif decrypt_data(data[block_total:block_total+0x8], cypher).startswith(b"\xeb\x9f\x56\xc9"):
        output += decrypt_data(data[header_size:block_total], cypher)
        logging.debug("without header")
    else:
        logging.error("Error, invalid data")
    return output

def decrypt_rom(mupdate, fname):
    """
        Decrypts all the ROM according to the header crypto flag
        Returns a decrypted chunk with the correct header
    """
    logging.info("Decrypting the ROM file")
    # Remove cipher indicator from rom header
    rom_header = open(fname, "rb").read(0x80)
    rom_header = rom_header[:12] + b"\x00" + rom_header[13:]
    output = rom_header
    data = mupdate.rawdata

    for _ in tqdm(range(mupdate.header.rom_blocks), "Decrypting blocks"):
        block = decrypt_block(mupdate, data)
        data = data[len(block):]
        output += block
    return output

def print_common_header(hdr):
    """
        Print the informations contained in the header common to both
        the blocks and the ROM
    """
    print("header size 0x%x" % hdr.header_size)
    print("header CRC32: 0x%x" % hdr.header_crc)
    print("header format 0x%x" % hdr.header_format)
    print("Image cryptography: %s" % get_crypto(hdr.crypto_type))
    print("header flags 0x%x" % hdr.header_flags)
    print("content size 0x%x" % hdr.length)

def print_block_info(blk):
    """
        Print informations contained in the block header
    """
    print("Blk name %s" % (blk.blk_name))
    print("Blk version %s" % (blk.blk_version))
    print("Blk total 0x%x" % (blk.block_total))
    print("Blk cryptography: %s" % get_crypto(blk.cipher))
    print("Blk type: %s" % (get_block_type(blk.block_type)))

def dump_block(blk):
    """
        Dump a block to its name
    """
    name = blk.hdr.blk_name
    logging.info("Dumping block %s of size %d",
                 name + ".bin",
                 blk.hdr.common_header.length)

    data = blk.data[:blk.hdr.common_header.length]

    if blk.hdr.cipher == 1:
        logging.info("Block is compressed, decompressing it")
        data = lzma.decompress(data)
    elif blk.hdr.cipher == 3:
        logging.info("Block is ciphered with CIPHER3, decrypting")
        data = decrypt_data(data, blk.hdr.cipher)
    elif blk.hdr.cipher != 0:
        logging.error("Block cryptography is not yet supported")
    with open(name + ".bin", "wb") as out:
        out.write(data)

def show_rom_info(mupdate, fname=""):
    """
        Show the rom header informations, and walks the blocks
    """
    print("ROM magic: 0x%s" % hexlify(mupdate.header.magic))
    print_common_header(mupdate.header.common_header)

    print("ROM verify: 0x%x" % mupdate.header.rom_verify)
    print("ROM blocks: 0x%x" % mupdate.header.rom_blocks)
    print("ROM dev ID: %d" % mupdate.header.rom_dev_id)
    print("ROM hw ID: %d" % mupdate.header.rom_hw_id)
    print("ROM sw ID: %d" % mupdate.header.rom_sw_id)
    print("ROM dev name: %s" % mupdate.header.rom_dev_name)
    print("ROM oem name: %s" % mupdate.header.rom_oem_name)
    print("ROM  version: %s" % mupdate.header.rom_version)

    for i in range(16):
        rom_cid = mupdate.header.rom_rom_cid_array[i]
        if rom_cid != 0:
            print("Rom rom cid %d : %d" %(i, rom_cid))

    if mupdate.header.common_header.crypto_type == 0:
        logging.info("Firmware is unencrypted, showing blocks info")
        for i in range(mupdate.header.rom_blocks):
            print_common_header(mupdate.blocks[i].hdr.common_header)
            print_block_info(mupdate.blocks[i].hdr)
    else:
        data = decrypt_rom(mupdate, fname)
        data = bytes(data)
        update = yealinkrom.Yealinkrom.from_bytes(data)
        show_rom_info(update)


def show_info(fname):
    """
        Dump the informations contained in the structure
    """
    mupdate = yealinkrom.Yealinkrom.from_file(fname)
    show_rom_info(mupdate, fname)


def dump_blocks(update):
    """
        Dump all the blocks of a ROM image
    """
    for i in tqdm(range(update.header.rom_blocks), "Dumping blocks"):
        dump_block(update.blocks[i])


def dump(fname):
    """
        Dump the blocks
    """
    mupdate = yealinkrom.Yealinkrom.from_file(fname)

    if mupdate.header.common_header.crypto_type == 0:
        logging.info("Firmware is unencrypted, directly dumping blocks")
        dump_blocks(mupdate)
    else:
        logging.info("The firmware looks encrypted, we have to decrypt it")
        data = decrypt_rom(mupdate, fname)
        data = bytes(data)
        mupdate = yealinkrom.Yealinkrom.from_bytes(data)

        dump_blocks(mupdate)


def main():
    """
        Argument parsing and dispatching
    """
    actions = {
        "dump": dump,
        "info": show_info
    }
    parser = argparse.ArgumentParser("ROM parsing script for yealink firmwares")
    parser.add_argument("action", choices=actions.keys())
    parser.add_argument("update", help="the update file")

    parser.add_argument("--verbose", "-v", help="verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    actions[args.action](args.update)


if __name__ == "__main__":
    main()
