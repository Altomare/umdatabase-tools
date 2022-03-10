import argparse
import hashlib
import json
import os
import pprint
import pycdlib
import struct
import sys
import zlib

from io import BytesIO
from enum import IntEnum


class SFODataFormat(IntEnum):
    # Values are read backward
    UTF8_NOTERM = 0x0004
    UTF8 = 0x0204
    INT32 = 0x0404


class SFOIndexTableEntry:
    def __init__(self, raw, offset):
        fields = struct.unpack('<HHIII', raw[offset: offset + 0x10])
        self.key_offset = fields[0]
        self.data_fmt = SFODataFormat(fields[1])
        self.data_len = fields[2]
        self.data_max_len = fields[3]
        self.data_offset = fields[4]


class SFO:
    def __init__(self, raw_sfo):
        # Read header
        assert(raw_sfo[:0x4] == b"\x00PSF")
        version_minor = struct.unpack("<I", raw_sfo[0x5:0x8] + b"\x00")[0]
        self.version = f"{raw_sfo[0x04]}.{version_minor}"
        self.key_table_start, self.data_table_start, self.table_entries = \
            struct.unpack('<III', raw_sfo[0x08:0x14])

        # Read index table entries
        self.idx_table = []
        for idx in range(self.table_entries):
            self.idx_table.append(
                SFOIndexTableEntry(raw_sfo, 0x14 + idx * 0x10))

        # Read data entries
        self.data = {}
        for i in range(len(self.idx_table)):
            self._read_entry(raw_sfo, i)

    def _read_entry(self, raw_sfo, idx):
        # Offsets
        key_table_start = self.key_table_start
        data_table_start = self.data_table_start
        entry = self.idx_table[idx]

        # Read key from key table
        k_start = key_table_start + entry.key_offset
        if idx == len(self.idx_table) - 1:
            k_end = data_table_start
        else:
            k_end = key_table_start + self.idx_table[idx + 1].key_offset
        key = raw_sfo[k_start: k_end].decode('utf8').rstrip("\x00")

        # Read data from data table
        d_start = data_table_start + entry.data_offset
        d_end = d_start + entry.data_len
        if entry.data_fmt == SFODataFormat.INT32:
            data = int.from_bytes(raw_sfo[d_start: d_end], "little")
        else:
            data = raw_sfo[d_start: d_end].decode('utf8').rstrip("\x00")

        self.data[key] = data

    def dump(self):
        dump = {}
        dump["version"] = self.version
        dump["fields"] = {}
        for key in self.data.keys():
            dump["fields"][key] = self.data[key]
        return dump


def decdatetime_to_str(raw, offset):
    val = struct.unpack_from("4s2s2s2s2s2s2sb", raw, offset)
    year = val[0].decode('ascii')
    month = val[1].decode('ascii')
    day = val[2].decode('ascii')
    hour = val[3].decode('ascii')
    minute = val[4].decode('ascii')
    second = val[5].decode('ascii')
    csec = val[6].decode('ascii')
    zone = val[7]
    return f"{year}-{month}-{day} {hour}:{minute}:{second}.{csec} ({zone})"


def gen_hashes(filestream, out):
    def read_in_chunks(file_object, chunk_size):
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    filestream.seek(0)
    prev_crc32 = 0
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    for piece in read_in_chunks(filestream, 0x10000):
        prev_crc32 = zlib.crc32(piece, prev_crc32)
        sha1.update(piece)
        md5.update(piece)
        sha256.update(piece)

    out["hashes"] = {
        "crc32": format(prev_crc32 & 0xFFFFFFFF, 'x').zfill(8),
        "sha1": sha1.hexdigest().zfill(40),
        "md5": md5.hexdigest().zfill(32),
        "sha256": sha256.hexdigest().zfill(64),
    }


def decode_string(raw, offset, size):
    raw_str = struct.unpack_from(f"{size}s", raw, offset)[0]
    return raw_str.decode('ascii').strip()


def get_pvd_dump(filestream, out):
    # Locate PVD sector, starting from sector 0x10
    # See: https://wiki.osdev.org/ISO_9660#Volume_Descriptors
    filestream.seek(0x8000)
    raw_sector = filestream.read(0x800)
    while raw_sector[0] != 0xFF:
        if raw_sector[0] == 0x01:
            pvd = {}
            pvd["volume_set_id"] = decode_string(raw_sector, 0xbe, 0x80)
            pvd["publisher"] = decode_string(raw_sector, 0x13e, 0x80)
            pvd["preparer"] = decode_string(raw_sector, 0x1be, 0x80)
            pvd["application_id"] = decode_string(raw_sector, 0x23e, 0x80)
            pvd["creation_date"] = decdatetime_to_str(raw_sector, 0x32d)
            pvd["modification_date"] = decdatetime_to_str(raw_sector, 0x33e)
            pvd["expiration_date"] = decdatetime_to_str(raw_sector, 0x34f)
            pvd["effective_date"] = decdatetime_to_str(raw_sector, 0x360)
            out["pvd"] = pvd
            return
        raw_sector = filestream.read(0x800)
    raise Exception("Could not find PVD")


def parse_umd_data(raw, out):
    umd_data = raw.decode('ascii')
    fields = umd_data.split('|')
    out["umd_data"] = {}
    out["umd_data"]["id"] = fields[0]
    out["umd_data"]["key"] = fields[1]
    out["umd_data"]["unknown"] = fields[2]
    out["umd_data"]["type"] = fields[3].strip(chr(0))


def iso_walk(path, out):
    """Generate hashes for all of the ISO files + SFO info dumps"""
    iso = pycdlib.PyCdlib()
    iso.open(path)
    out["tree"] = {}
    out["sfo_info"] = {}
    for dirname, dirlist, filelist in iso.walk(iso_path='/'):
        for file in filelist:
            if dirname == '/':
                full_name = '/' + file
            else:
                full_name = dirname + '/' + file

            sfo_file = dirname + "/" + file

            extracted = BytesIO()
            iso.get_file_from_iso_fp(extracted, iso_path=sfo_file)
            raw_file = extracted.getvalue()

            sha1 = hashlib.sha1()
            sha1.update(raw_file)
            out["tree"][full_name] = sha1.hexdigest().zfill(40)

            if file == 'UMD_DATA.BIN':
                parse_umd_data(raw_file, out)

            if file.endswith('.SFO'):
                sfo = SFO(raw_file)
                out["sfo_info"][sfo_file] = sfo.dump()
    iso.close()


def gen_submission(iso, out):
    if not os.path.exists(iso):
        print(f"Unable to access {iso}")
        return

    report = {}
    report["size"] = os.stat(iso).st_size
    with open(iso, 'rb') as f:
        gen_hashes(f, report)
        get_pvd_dump(f, report)
    iso_walk(iso, report)

    with open(out, 'w', encoding='utf8') as f:
        f.write(json.dumps(report))

    pprint.pprint(report)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Extract data from a PSP iso into a json file for UMDB')
    parser.add_argument('iso', type=str, help='PSP Iso file')
    parser.add_argument('--out', dest='out_file', default=None,
                        help='output file')
    args = parser.parse_args()

    out = args.out_file
    if not out:
        out = args.iso + '.json'

    if os.path.exists(out):
        print("Output file already exists, aborting.")
        input("Press any key")
        sys.exit(1)
    gen_submission(args.iso, out)
