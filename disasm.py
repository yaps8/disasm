#!/usr/bin/python2.7

import sys
import os
import distorm3
import networkx as nx
import matplotlib.pyplot as plt
import pydot

if len(sys.argv) > 1:
    path = sys.argv[1]
else:
    path = "/home/aurelien/trace/telock99-hostname.bin/telock99-hostname.bin.exe.snapshot2"
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

def disas_at(offset, f):
    f.seek(offset)
    l = distorm3.Decode(offset, f.read(16), distorm3.Decode32Bits)[0]
    return l

# s = int_tab_to_str(bs, 0, 8)
# s = "90"
# l = distorm3.Decode(eip, f.read(), distorm3.Decode32Bits)
# ib = l[0]
# print "0x%08x (%02x) %-20s %s" % (ib[0],  ib[1],  ib[3],  ib[2])
print disas_at(0x49, f)
print disas_at(0x40, f)
# for ib in l:
#     print "0x%08x (%02x) %-20s %s" % (ib[0],  ib[1],  ib[3],  ib[2])


def disas_file(virt_offset, f, fsize):
    g = nx.Graph()
    g.add_nodes_from(range(virt_offset, fsize+virt_offset))
    # nx.draw_graphviz(g)
    # nx.write_dot(g, 'file.dot')
    print "blah"

disas_file(0, f, fsize)