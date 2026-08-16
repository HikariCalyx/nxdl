import sys, struct

base = r"D:\user_profile\Documents\GitHub\nxldl\reference"
old = open(base + r"\Maplestory_Classic.exe.old", "rb").read()
new = open(base + r"\Maplestory_Classic.exe.new", "rb").read()
patch = open(base + r"\TWFwbGVzdG9yeV9DbGFzc2ljLmV4ZQ==.nxdlpatch", "rb").read()

class Reader:
    def __init__(self, b):
        self.b = b
        self.pos = 0
    def u8(self):
        v = self.b[self.pos]; self.pos += 1; return v
    def u16(self):
        v = struct.unpack("<H", self.b[self.pos:self.pos+2])[0]; self.pos += 2; return v
    def u32(self):
        v = struct.unpack("<I", self.b[self.pos:self.pos+4])[0]; self.pos += 4; return v

# Updated decoder: 0x04 = u8 offset + u16 count (seek), matching fixed Program.cs
p = Reader(patch)
fpos = 0
out = bytearray()
n04_nonzero = 0
while p.pos < len(patch):
    op = p.u8()
    if op == 0:
        break
    if op == 0x04:
        off = p.u8(); n = p.u16()
        if off != 0:
            n04_nonzero += 1
        out += old[off:off+n]
        fpos = off + n
    elif op == 0x10:
        off = p.u16(); n = p.u8(); out += old[off:off+n]; fpos = off + n
    elif op == 0x14:
        off = p.u16(); n = p.u16(); out += old[off:off+n]; fpos = off + n
    elif op == 0x20:
        off = p.u32(); n = p.u8(); out += old[off:off+n]; fpos = off + n
    elif op == 0x24:
        off = p.u32(); n = p.u16(); out += old[off:off+n]; fpos = off + n
    elif op == 0x28:
        off = p.u32(); n = p.u32(); out += old[off:off+n]; fpos = off + n
    elif op == 0x40:
        n = p.u8(); out += patch[p.pos:p.pos+n]; p.pos += n
    elif op == 0x44:
        n = p.u16(); out += patch[p.pos:p.pos+n]; p.pos += n
    elif op == 0x48:
        n = p.u32(); out += patch[p.pos:p.pos+n]; p.pos += n
    else:
        raise Exception("unknown opcode %02x at %x" % (op, p.pos-1))

outb = bytes(out)
print("decoded len:", len(outb), "== old len:", len(outb) == len(old))
print("0x04 ops with nonzero offset:", n04_nonzero)
print("decoded == new:", outb == new)

def pe_checksum(data):
    lfa = struct.unpack("<I", data[0x3C:0x40])[0]
    csum_off = lfa + 4 + 20 + 64
    b = bytearray(data)
    b[csum_off:csum_off+4] = b"\x00\x00\x00\x00"
    s = 0
    i = 0
    n = len(b)
    while i + 1 < n:
        s += struct.unpack("<H", b[i:i+2])[0]
        s = (s & 0xFFFF) + (s >> 16)
        i += 2
    if i < n:
        s += b[i]
    s = (s & 0xFFFF) + (s >> 16)
    return (s + n) & 0xFFFFFFFF

lfa = struct.unpack("<I", outb[0x3C:0x40])[0]
csum_off = lfa + 4 + 20 + 64
stored = struct.unpack("<I", outb[csum_off:csum_off+4])[0]
print("decoded checksum: stored=0x%08x computed=0x%08x" % (stored, pe_checksum(outb)))
