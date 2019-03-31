#!/usr/bin/env python3

import argparse
import struct
from io import BufferedReader
import os


class Record:
    # magic header - 4 bytes

    # version - 1 byte
    # type - 1 byte
    # format - 1 byte
    # pad - 1 byte

    # start - 8 bytes
    # size - 8 bytes
    # block - 4 bytes
    # block count - 4 bytes
    # name - 16 bytes
    # backup - 16 bytes
    # hash - 32 bytes
    # reserved - 24 bytes
    # crc32 - 4 bytes
    # status - 1 byte
    # magic footer - 4 bytes
    # padding - 7 bytes
    MXP_RECORD_FMT = '<4sBBBxQQII16s16s32s24x4sc4s7x'
    MXP_MAGIC_HEADER = b'MXPT'
    MXP_MAGIC_FOOTER = b'TPXM'
    __slots__ = ['header', 'version', 'type', 'format', 'start', 'size', 'block', 'block_count', 'name', 'footer']

    def __init__(self, buffer):
        record = struct.unpack(self.MXP_RECORD_FMT, buffer)
        self.header = record[0]
        self.version = record[1]
        self.type = record[2]
        self.format = record[3]
        self.start = record[4]
        self.size = record[5]
        self.block = record[6]
        self.block_count = record[7]
        self.name = record[8].split(b'\0', 1)[0].decode('ascii')
        self.footer = record[13]

    def tag(self):
        return self.type == 0

    def end(self):
        return self.start + self.size

    @staticmethod
    def recordsz():
        return struct.calcsize(Record.MXP_RECORD_FMT)

    @staticmethod
    def isrecord(buffer):
        record = struct.unpack(Record.MXP_RECORD_FMT, buffer)
        return record[0] == Record.MXP_MAGIC_HEADER and record[13] == Record.MXP_MAGIC_FOOTER


parser = argparse.ArgumentParser('mstarfwcutter - cuts up mstar firmware dumps')
parser.add_argument('--input', type=argparse.FileType('rb'), required=True, help='input file')
parser.add_argument('--output', type=str, required=True, help='output directory')

args = parser.parse_args()

input: BufferedReader = args.input

print(Record.recordsz())

print('Looking for first partition record in %s..' % input.name)
off = 0
while True:
    input.seek(off)
    off += 1
    buffer = input.read(Record.recordsz())
    if buffer is None:
        print('reached end of input but didn\'t find first partition record')
        exit(1)
    if Record.isrecord(buffer):
        input_offset = input.tell() - Record.recordsz()
        print('partition first partition record at %x' % input_offset)
        input.seek(input_offset)
        break

os.mkdir(args.output)

for i in range(0, 16):
    buffer = input.read(Record.recordsz())
    next_record_offset = input.tell()
    record = Record(buffer)
    if record.tag():
        break
    print('%d - %s, type %d: %x -> %x' % (i, record.name, record.type, record.start, record.end()))
    output = open('%s/%s.bin' % (args.output, record.name), mode='wb')
    input.seek(record.start)
    partition = input.read(record.size)
    output.write(partition)
    output.close()
    input.seek(next_record_offset)
