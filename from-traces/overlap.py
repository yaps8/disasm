#!/usr/bin/python2.7
# coding: utf-8

import sys

if len(sys.argv) > 1:
    path = sys.argv[1]
else:
    path = "trace3-addr-size02"

print "in", path
f = open(path, "rb")
lines = [line.strip() for line in f]
f.close()
done = set()

for i in lines:
    a = i.split()
    addr_i = int(a[0], 16)
    size_i = int(a[1], 16)
    # print "addr:", hex(addr), "size:", size
    for j in lines:
        a = j.split()
        addr_j = int(a[0], 16)
        size_j = int(a[1], 16)
        if frozenset([addr_i, addr_j]) not in done:
            if addr_i != addr_j:
                if addr_i <= addr_j <= addr_i + size_i - 1 or addr_i <= addr_j + size_j - 1 <= addr_i + size_i - 1:
                    print "conflict:"
                    print hex(addr_i), size_i
                    print hex(addr_j), size_j
                    print ""
            done.add(frozenset([addr_i, addr_j]))