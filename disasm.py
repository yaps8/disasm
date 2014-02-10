#!/usr/bin/python2.7

import sys
import os
import distorm3
import networkx as nx
import matplotlib.pyplot as plt
import pydot


def target(str):
    t = str.split()
    if t[0] in ["jz", "jnz", "jmp"]:
        target = int(t[1],16)
        if t[0] == "jmp":
            return True, target, False
        else:
            return True, target, True
    else:
        return False, 0, False


class Instruction:
    def __init__(self, d_inst):
        self.addr = d_inst[0]
        self.size = d_inst[1]
        self.desc = d_inst[2].lower()
        i, t, jcc = target(d_inst[2].lower())
        self.has_target = i
        self.target = t
        self.is_jcc = jcc

    def __str__(self):
        s = str(self.addr) + ", " + str(self.size) + ", " + self.desc
        if self.has_target:
            s += ", target: " + hex(self.target)
        if self.is_jcc:
            s += ", is_jcc"
        s += "."
        return s

class BasicBlock:
    def __init__(self, addr, size):
        self.addr = addr
        self.size = size

if len(sys.argv) > 1:
    path = sys.argv[1]
else:
    # path = "/home/aurelien/trace/telock99-hostname.bin/telock99-hostname.bin.exe.snapshot2"
    path = "ex.bin"
f = open(path, "rb")
fsize = os.path.getsize(path)

# bs = []
# try:
#     byte = f.read(1)
#     k = 0
#     while len(byte) > 0:
#         s = '{0:02x}'.format(ord(byte[0]))
#         i = int(s, 16)
# #        print i
# #        print "%d %x" % (i,i)
#         byte = f.read(1)
#         bs.append(i)
# finally:
#     # f.seek(0)
#     f.close()


# def int_tab_to_str(tab, begin, size):
#     s = ""
#     for i in range(begin, begin+size):
#         s += str(tab[i])
#     return s

def disas_at(offset, f, size):
    if offset < size:
        f.seek(offset)
        l = distorm3.Decode(offset, f.read(min(16, size-offset)), distorm3.Decode32Bits)[0]
        return Instruction(l)
    else:
        raise "Error in disas_at"


# s = int_tab_to_str(bs, 0, 8)
# s = "90"
# l = distorm3.Decode(eip, f.read(), distorm3.Decode32Bits)
# ib = l[0]
# print "0x%08x (%02x) %-20s %s" % (ib[0],  ib[1],  ib[3],  ib[2])
# print disas_at(0x49, f, fsize)
# print disas_at(0x40, f, fsize)
# for ib in l:
#     print "0x%08x (%02x) %-20s %s" % (ib[0],  ib[1],  ib[3],  ib[2])

def get_first_block_having(g, inst):
    return 0

# def make_basic_block(beginning, end, addr, g, f):
#     block = BasicBlock(beginning, beginning)
#     while beginning <= addr <= end:
#         inst = disas_at(addr, f)
#
#         (exist, b) = get_first_block_having(inst)
#
#         if exist:
#             ad=b.addr
#             if addr != ad:
#                 b=split_block(b, addr, g)
#
#             if inst == "ERR":
#                 return block
#             else
#                 connect_to(g, block, b)
#                 return block
#         else:
#             add_inst_to_block(inst, block)
#             if has_target(inst):
#                 target=get_target_of(inst)
#                 if beginning <= target <= end:
#                     b=make_basic_block(beginning, end, target, g, f)
#                     connect_to(g, block, b)
#
#                 if is_jcc(inst):
#                     b=make_basic_block(beginning, end, addr+len(addr), g, f) #TODO len ?
#                     connect_to(g, block, b)
#
#                 return block
#             else:
#                 addr=addr+len(inst)
#     return block



def disas_segment(beginning, end, f):
    g = nx.Graph()



def disas_file(virt_offset, f, fsize):
    g = nx.Graph()
    g.add_nodes_from(range(virt_offset, fsize+virt_offset))
    # nx.draw_graphviz(g)
    # nx.write_dot(g, 'file.dot')
    print "blah"

disas_file(0, f, fsize)

for i in range(fsize):
    print disas_at(i, f, fsize)