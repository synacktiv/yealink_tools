# coding: utf-8
#!/usr/bin/env python3

"""
    YAFFS2 parser for yealink encrypted filesystem
    (c) 2019 - Synacktiv - www.synacktiv.com

    The Yaffs and Yaffs structure are issued from two Kaitai struct generated files

    Licensed under the "THE BEER-WARE LICENSE" (Revision 42):
    Tristan P. wrote this file. As long as you retain this notice you
    can do whatever you want with this stuff. If we meet some day, and you think
    this stuff is worth it, you can buy me a beer or coffee in return
"""

import argparse
import struct
import logging
import os

from tqdm import tqdm
from yaffs import Yaffs
from yaffstag import Yaffstag

from yealink_crypto import cypher3_decrypt


class YaffsObject():
    """
        Custom variation of object
    """

    def __init__(self, object_header, tag):
        """
            Initialize an object from a kaitai generated header and spare
        """

        self.pid = object_header.parent_obj_id
        self.type = object_header.obj_type
        self.file_size = object_header.file_size_low
        if object_header.name:
            self.name = object_header.name
        else:
            # root folder?
            self.name = "/"
        self.obj_id = tag.obj_id
        logging.debug("Got a new object: 0x%x : %s", self.obj_id, self.name)
        logging.debug("Object size: 0x%x", self.file_size)

    def __repr__(self):
        mstr = "YaffsObject(0x%x, %s)" % (self.obj_id, self.name)
        return mstr

    def ls(self, level=0):
        """
            This should be implemented in the specific object
        """
        raise NotImplementedError

    @staticmethod
    def factory(header, spare):
        """
            Generates an object according to the type specified in the headers
        """
        try:
            # the first 512 bytes may be ciphered
            object_header = Yaffs.from_bytes(header)
            tag = Yaffstag.from_bytes(spare)
        except Exception as e:
            logging.exception(e)
            logging.warning("Error, cannot generate the datastructures from the supplied buffers")

            raise e

        if object_header.obj_type == Yaffs.ObjType.directory:
            return YaffsDirectory(object_header, tag)
        if object_header.obj_type == Yaffs.ObjType.file:
            return YaffsFile(object_header, tag)
        if object_header.obj_type == Yaffs.ObjType.symlink:
            return YaffsSymlink(object_header, tag)
        logging.warning("Unknown type %s", object_header.obj_type)
        return YaffsObject(object_header, tag)

class YaffsDirectory(YaffsObject):
    """
        Implementation of a directory
    """

    def __init__(self, header, spare):
        YaffsObject.__init__(self, header, spare)
        self.children = []

    def add_children(self, obj):
        """
            Add a children of a directory
        """
        if obj.obj_id != 1:
            self.children.append(obj)

    def ls(self, level=0):
        if level == 0:
            print(self.name)
        else:
            print("%s/%s" % ('  '*level, self.name))
        for child in self.children:
            child.ls(level+1)

    def __repr__(self):
        mstr = "YaffsDirectory(0x%x, %s)" % (self.obj_id, self.name)
        return mstr

class YaffsFile(YaffsObject):
    """
        A file, containing one or more data blocks
    """
    def __init__(self, header, spare):
        YaffsObject.__init__(self, header, spare)
        self.nb_blocks = int(self.file_size / 0x800) + 1
        if self.file_size == 0:
            self.nb_blocks = 0
        self.data_blocks = [None for _ in range(self.nb_blocks)]

    def add_data_block(self, block, tag):
        """
            Add a chunk of data on the file
        """
        if tag.seq_id > len(self.data_blocks):
            logging.error("Too many data blocks for this file")
            raise IOError
        if self.data_blocks[tag.seq_id -1] is not None:
            logging.error("Already got data for this seq id")
        else:
            self.data_blocks[tag.seq_id-1] = block.data[:tag.nbytes]

    def get_data(self):
        """
            Return the reconstructed file
        """
        data = bytearray()
        for i, block in enumerate(self.data_blocks):
            if block is not None:
                data += block
            else:
                logging.warning("Missing data block %d/%d on file %s", i,
                                self.nb_blocks, self.name)
        return data

    def ls(self, level=0):
        """
            List the file and its size
        """
        print("%s%s %d" % ("  "*level, self.name, self.file_size))

    def __repr__(self):
        mstr = "YaffsFile(0x%x, %s)" % (self.obj_id, self.name)
        return mstr

class YaffsSymlink(YaffsObject):
    """
        A symlink pointing to another object
    """
    def __init__(self, header, tag):
        YaffsObject.__init__(self, header, tag)

        self.alias = header.alias

    def ls(self, level=0):
        """
            List the symlink and its alias
        """
        print("%s%s -> %s" % ("  "*level, self.name, self.alias))

    def __repr__(self):
        mstr = "YaffsFile(0x%x, %s)" % (self.obj_id, self.name)
        return mstr


class YaffsBlock():
    """
        The block, composed of 1 2048 bytes chunk + 64 bytes tag (the tag being OOB)
    """
    YAFFS_BLOCK_HEADERS = [struct.pack("I", i) for i in range(5)]

    def __init__(self, data):
        self.spare = data[0x800:0x800+0x40]
        self.is_header = False

        decrypted = cypher3_decrypt(data[:0x200])

        for header in self.YAFFS_BLOCK_HEADERS:
            if decrypted.startswith(header):
                # we got a correct yaffs chunk header
                self.is_header = True
                break
        if self.is_header:
            self.data = decrypted + data[0x200:0x800]
        else:
            self.data = data[:0x800]


class YaffsFileSystem():
    """
        Semi ordered collection of Yaffs objects
    """

    def __init__(self):
        self.objects = {}
        self.directories = {}
        self.files = {}

    def add_object(self, obj):
        """
            Add an object to the filesystem
        """
        logging.debug("Adding object with id %d pid %d name: %s", obj.obj_id, obj.pid, obj.name)
        logging.debug("Object name: %s", obj.name)

        if obj.obj_id in self.objects:
            logging.warning("error: object already in the list!")
        else:
            self.objects[obj.obj_id] = obj

        if obj.type == Yaffs.ObjType.directory:
            self.directories[obj.obj_id] = obj

        elif obj.type == Yaffs.ObjType.file:
            self.files[obj.obj_id] = obj

        if obj.pid not in self.directories.keys():
            logging.warning("Parent %d of object %s not known", obj.pid, obj.name)
        else:
            self.directories[obj.pid].add_children(obj)

    def add_block(self, block):
        """
            Add a new object or a data block to an existing object
        """

        if block.is_header:
            obj = YaffsObject.factory(block.data, block.spare)
            self.add_object(obj)
        else:
            tag = Yaffstag.from_bytes(block.spare)
            logging.debug("Got data block %d for file %d", tag.seq_id, tag.obj_id)

            if tag.obj_id not in self.files.keys():
                logging.error("Unknown file ID %d", tag.obj_id)
            else:
                self.files[tag.obj_id].add_data_block(block, tag)

    def add_blocks(self, blocks):
        """
            Construct the filesystem from a list of blocks
        """
        for block in tqdm(blocks, "Reconstructing objects"):
            self.add_block(block)
        logging.info("Reconstructing objects and structure: DONE")


def reconstruct_filesystem(fname):
    """
        Tries to reconstruct a valid YAFFS filesystem from a dumped file
    """
    blocks = []

    data = open(fname, "rb").read()
    filesystem = YaffsFileSystem()

    blocks = []
    for index in tqdm(range(0, len(data)-0x840, 0x840), "Generating blocks"):
        blocks.append(YaffsBlock(data[index:index+0x840]))
    filesystem.add_blocks(blocks)
    return filesystem

def dump_directories(root, filesystem):
    """
        Recreates the filesystem arborescence inside the new directory
    """
    def walk_directory(base_dir):
        """
            Recursively walk directory
        """
        os.mkdir(base_dir.name)
        os.chdir(base_dir.name)
        for child in base_dir.children:
            if isinstance(child, YaffsDirectory):
                walk_directory(child)
            elif isinstance(child, YaffsFile):
                with open(child.name, "wb") as out:
                    out.write(child.get_data())
        os.chdir("..")

    if os.path.exists(root):
        logging.error("Existing directory, aborting")
        raise OSError

    os.mkdir(root)
    os.chdir(root)
    for child in filesystem.directories[1].children:
        if isinstance(child, YaffsDirectory):
            walk_directory(child)
    os.chdir("..")


def dump_fs(args):
    """
        Dump the content of all the files in a new directory
    """
    filesystem = reconstruct_filesystem(args.file)
    if filesystem is None:
        logging.error("Error reconstructing filesystem, aborting")
        return

    logging.info("Dumping filesystem in directory %s", args.output)
    dump_directories(args.output, filesystem)
    logging.info("Extraction has finished, good luck!")


def list_fs(args):
    """
        Tree like printing of the filesystem
    """
    filesystem = reconstruct_filesystem(args.file)
    if filesystem is None:
        logging.error("Error reconstructing filesystem, aborting")
    elif 1 not in filesystem.directories.keys():
        logging.error("No root directory in the filesystem")
    else:
        filesystem.directories[1].ls()

def main():
    """
        Argument dispatching
    """
    parser = argparse.ArgumentParser("Yealink YAFFS2 parser")

    subparsers = parser.add_subparsers(help="Subcommands")
    ls_arg = subparsers.add_parser("ls", help="List the content of the filesystem")
    dump = subparsers.add_parser("dump", help="Dump the content of the filesystem")

    dump.add_argument("--output", "-o", help="The output directory", default="dumped")

    ls_arg.set_defaults(func=list_fs)
    dump.set_defaults(func=dump_fs)

    parser.add_argument("file", help="The file to parse")
    parser.add_argument("--verbose", "-v", help="verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # execute the user's action
    args.func(args)


if __name__ == "__main__":
    main()
