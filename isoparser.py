import argparse
import struct


class IsoHeader:
    def __init__(self, pvd):
        vol_info = struct.unpack_from("<i44xh2xi ", pvd, 80)
        self.volume_space_size = vol_info[0]
        self.block_size = vol_info[1]
        self.path_table_size = vol_info[2]

        l_table = struct.unpack_from("<ii", pvd, 140)
        self.l_table_off = l_table[0]
        self.opt_l_table_off = l_table[1]

        self.root_dir = DirEntry(pvd, 0x9c)

    def dump(self):
        print("Volume Space Size", self.volume_space_size)
        print("Logical Block Size", self.block_size)
        print("Path Table Size", self.path_table_size)
        print("Type-L Path Table", self.l_table_off)
        print()


class DirEntry:
    def __init__(self, raw, offset):
        header = struct.unpack_from("<bb i4x i4x 7s bbb h2x b", raw, offset)
        self.length = header[0]
        self.ext_length = header[1]
        self.extent = header[2]
        self.data_length = header[3]
        self.datetime = header[4]
        self.flags = header[5]
        self.unit_size = header[6]
        self.interleave_size = header[7]
        self.seqnum = header[8]
        self.name_len = header[9]
        self.name = struct.unpack_from(f"<{self.name_len}s", raw, offset + 0x21)[0]
        self.name = self.name.decode('ascii')

    def print(self):
        entry_type = "DirEntry" if self.flags & 0x2 else "File"
        print(f"{entry_type} '{self.name}' "
              f"Flags: {hex(self.flags)} "
              f"Extent: {self.data_length} bytes at {self.extent}")


class PathTableEntry:
    def __init__(self, raw, offset):
        data = struct.unpack_from("<bbih", raw, offset)
        self.len = data[0]
        self.ext_len = data[1]
        self.extent = data[2]
        self.dir_nb = data[3]
        self.name = raw[offset + 8: offset + 8 + self.len].decode('ascii')
        # print(f"{self.len=}")
        # print(f"{self.ext_len=}")
        # print(f"")
        # print(f"{self.dir_nb} - {self.name} {self.extent=} {self.ext_len=}")

    def size(self):
        fullsize = 8 + self.len
        return fullsize + 1 if fullsize % 2 else fullsize


def get_pvd_header(filestream):
    # Locate PVD sector, starting from sector 0x10
    # See: https://wiki.osdev.org/ISO_9660#Volume_Descriptors
    filestream.seek(0x8000)
    raw_sector = filestream.read(0x800)
    while raw_sector[0] != 0xFF:
        if raw_sector[0] == 0x01:
            return IsoHeader(raw_sector)
        raw_sector = filestream.read(0x800)
    raise Exception("Could not find PVD")


def walk_dirs(stream, root_dir, out=None):
    if not out:
        out = []

    stream.seek(root_dir.extent * 0x800)
    data = stream.read(0x800)

    idx = 0
    i = 0
    while data[idx]:
        entry = DirEntry(data, idx)
        if i >= 2:
            entry.print()
        if entry.flags & 0x02 and i >= 2:
            out.append(entry)
            walk_dirs(stream, entry, out)
        idx += entry.length
        i += 1

    return out


def parse_iso(file):
    with open(file, 'rb') as f:
        header = get_pvd_header(f)
        # header.dump()

        f.seek(header.l_table_off * header.block_size)
        data = f.read(header.path_table_size)
        # print(data)
        idx = 0
        while idx < header.path_table_size:
            entry = PathTableEntry(data, idx)
            idx += entry.size()

        dirs = walk_dirs(f, header.root_dir)

        # data = f.read(header.block_size - idx)
        # print(data)
        # data = f.read(128)
        # print(data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Extract data from a PSP iso into a json file for UMDB')
    parser.add_argument('iso', type=str, help='PSP Iso file')
    args = parser.parse_args()

    print(args.iso)
    parse_iso(args.iso)
