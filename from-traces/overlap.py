#!/usr/bin/python2.7
# coding: utf-8

import sys


def conflict_in_subset(conflict, conflicts):
    for c in conflicts:
        if c != conflict and conflict.issubset(c):
            # print "subset of conflict detected!"
            return True
    return False


def set_to_str(c):
    s = ""
    for a in c:
        s += hex(a) + " "
    return s


def print_conflicts(conflicts):
    print "Conflicts:"
    s = ""
    for c in conflicts:
        s += set_to_str(c) + "\n"
    print s

if len(sys.argv) > 1:
    path = sys.argv[1]
else:
    path = "trace3-addr-size02"

if len(sys.argv) > 2 and sys.argv[2] == "-v":
    verbose = True
else:
    verbose = False

#print "in", path
f = open(path, "rb")
lines = [line.strip() for line in f]
f.close()
done = set()
addr = set()
min_addr = -1
max_addr = -1

for i in lines:
    a = i.split()
    addr_i = int(a[0], 16)
    size_i = int(a[1], 16)
    addr.add((addr_i, size_i))
    if min_addr == -1 or min_addr > addr_i:
        min_addr = addr_i
    if max_addr == -1 or max_addr < addr_i + size_i - 1:
        max_addr = addr_i + size_i - 1
    # print "addr:", hex(addr), "size:", size
    # for j in lines:
    #     a = j.split()
    #     addr_j = int(a[0], 16)
    #     size_j = int(a[1], 16)
    #     if frozenset([addr_i, addr_j]) not in done:
    #         if addr_i != addr_j:
    #             if addr_i <= addr_j <= addr_i + size_i - 1 or addr_i <= addr_j + size_j - 1 <= addr_i + size_i - 1:
    #                 print "conflict:"
    #                 print hex(addr_i), size_i
    #                 print hex(addr_j), size_j
    #                 print ""
    #         done.add(frozenset([addr_i, addr_j]))

conflicts = set()
addr_in_conflicts = set()

# print "  Initial conflicts..."
# for a in range(beginning, end):
#     conflict = []
#     for n in g.nodes():
#         if n.addr <= a <= n.addr + n.size - 1:
#             conflict.append(n)
#     if len(conflict) >= 2:
#         conflicts.add(frozenset(conflict))

addr_to_conflict = dict()
for n in addr:
    for i in range(n[0], n[0] + n[1]):
        if not i in addr_to_conflict:
            addr_to_conflict[i] = [n[0]]
        else:
            addr_to_conflict[i].append(n[0])

for i in range(min_addr, max_addr):
    if i in addr_to_conflict:
        if len(addr_to_conflict[i]) >= 2:
            addr_in_conflicts.add(i)
            conflicts.add(frozenset(addr_to_conflict[i]))

# print "  Removing Subsets..."
conflicts_in_subset = set()
for c in conflicts:
    if conflict_in_subset(c, conflicts):
        conflicts_in_subset.add(c)

for c in conflicts_in_subset:
    conflicts.remove(c)



if verbose:
    print len(conflicts), "conflict(s) found."
    print_conflicts(conflicts)
else:
    print len(conflicts)


