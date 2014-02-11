#!/usr/bin/python2.7
# coding: utf-8
from _socket import gaierror

import sys
import os
import distorm3
import networkx as nx
from networkx import dag
from random import randrange
import matplotlib.pyplot as plt
import pydot


def target(str):
    t = str.split()
    if t[0] in ["jz", "jnz", "jmp"]:
        target = int(t[1],16)
        if t[0] == "jmp":
            return True, target, False, False
        else:
            return True, target, True, False
    elif t[0] in ["call"]:
        return False, 0, False, True
    else:
        return False, 0, False, False


class Instruction:
    def __init__(self, d_inst):
        self.addr = d_inst[0]
        self.size = d_inst[1]
        self.desc = d_inst[2].lower()
        i, t, jcc, call = target(d_inst[2].lower())
        self.is_call = call
        self.has_target = i
        self.target = t
        self.is_jcc = jcc

    def __str__(self):
        s = str(hex(int(self.addr))) + ", " + str(hex(int(self.size))) + ", " + self.desc
        if self.has_target:
            s += ", target: " + hex(self.target)
        if self.is_jcc:
            s += ", is_jcc"
        s += "."
        return s


class BasicBlock:
    def __init__(self, addr):
        self.addr = addr
        self.size = 0
        self.insts = []

    def add_inst(self, inst):
        # check that the inst is just following the block
        if inst.addr != self.addr + self.size:
            print "Error in add_inst_to_block: inst does not follow block.", inst.addr, self.addr, self.size
        else:
            self.size += inst.size
            self.insts.append(inst.addr)

    def contains_inst(self, inst):
        return inst.addr in self.insts

    def insts_to_str(self):
        s=""
        for i in self.insts:
            inst = disas_at(i, f, fsize)
            s += str(hex(int(inst.addr))) + " " + inst.desc + "\\n"
        return s

    def insts_to_hex(self):
        return [hex(int(i)) for i in self.insts]

    def __str__(self):
        return "[" + str(hex(int(self.addr))) + " -> " + str(hex(int(self.addr+self.size-1))) + "] (" + str(hex(int(self.size))) + ")" \
            + " \\n " + self.insts_to_str()

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
        print "Error in disas_at"


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
    nodes = g.nodes()
    for b in nodes:
        # print "b: " + str(b)
        if b.contains_inst(inst):
            return True, b
    return False, None


def split_block(b, addr, g):
    # print "spliting " + str(b)
    b2 = BasicBlock(addr)
    b2.insts = [x for x in b.insts if x >= addr]
    b2.size = b.addr - addr + b.size
    g.add_node(b2)
    for e in g.out_edges(b, data=True):
        u, v, d = e
        g.add_edge(b2, v, attr_dict=d)
        g.remove_edge(u, v)
    connect_to(g, b, b2)
    b.size = addr - b.addr
    b.insts = [x for x in b.insts if x < addr]

    # print "into " + str(b)
    # print "and " + str(b2)
    # print ""

    return b2


def connect_to(g, block, b, color="black"):
    # print "linking ", block
    # print "to ", b
    # print color
    # print ""
    g.add_edge(block, b, color=color)


def make_basic_block(beginning, end, addr, g, f, fsize):
    # print "makebb with addr =", addr
    block = BasicBlock(addr)
    # g.add_node(block)

    while beginning <= addr <= end:
        # print "while with addr =", addr
        inst = disas_at(addr, f, fsize)
        # add_inst_to_block(inst, block)

        (exist, b) = get_first_block_having(g, inst)

        if exist:
            # print "exists"
            if addr != b.addr:
                b = split_block(b, addr, g)

            if block.size == 0:
                return b
            else:
                if not g.has_node(block):
                    g.add_node(block)
                connect_to(g, block, b)
                return block
        else:
            if not g.has_node(block):
                g.add_node(block)
            block.add_inst(inst)
            if inst.has_target:
                target = inst.target
                if beginning <= target <= end:
                    b = make_basic_block(beginning, end, target, g, f, fsize)
                    connect_to(g, block, b, "red")

                if inst.is_jcc:
                    b = make_basic_block(beginning, end, addr + inst.size, g, f, fsize)
                    connect_to(g, block, b)

                return block
            else:
                if inst.is_call:
                    return block
                else:
                    addr += inst.size
    return block


def compute_conflicts(g):
    conflicts = set()
    done = set()

    for n in g.nodes():
        for n2 in g.nodes():
            if (not frozenset([n.addr, n2.addr]) in done) and n != n2:
                if n.addr <= n2.addr <= n.addr + n.size - 1 or n.addr <= n2.addr + n2.size - 1 <= n.addr + n.size - 1:
                    done.add(frozenset([n.addr, n2.addr]))
                    conflicts.add((n, n2))
    return conflicts


def conflict_resolved(g, conflict, node_to_remove, conflicts_to_remove):
    if g.has_node(node_to_remove):
        g.remove_node(node_to_remove)
    conflicts_to_remove.add(conflict)


def update_conflicts(g, conflicts, conflicts_to_remove):
    for c in conflicts:
        n, n2 = c
        if (not g.has_node(n)) or (not g.has_node(n2)):
            conflicts_to_remove.add(c)

    for c in conflicts_to_remove:
        conflicts.remove(c)


def resolve_conflicts_step1(g, conflicts, beginning):
    # Step 1: beginning vs other -> beginning
    conflicts_to_remove = set()
    for c in conflicts:
        n, n2 = c
        # Nodes n and n2 are in conflict
        if n.addr == beginning:
            conflict_resolved(g, c, n2, conflicts_to_remove)
        elif n2.addr == beginning:
            conflict_resolved(g, c, n, conflicts_to_remove)

    update_conflicts(g, conflicts, conflicts_to_remove)


def resolve_conflicts_step2(g, conflicts, beginning):
    # Step 2: remove common ancestors of nodes in conflict
    conflicts_to_remove = set()
    for c in conflicts:
        n, n2 = c
        if g.has_node(n) and g.has_node(n2):
            # Nodes n and n2 are in conflict
            a_n = dag.ancestors(g, n)
            a_n2 = dag.ancestors(g, n2)
            inter = a_n.intersection(a_n2)

            for nn in inter:
                g.remove_node(nn)
                # conflit_resolved(g, c, nn, conflicts_to_remove)

    update_conflicts(g, conflicts, conflicts_to_remove)


def resolve_conflicts_step3(g, conflicts, beginning):
    # Step 3: take the one with the more ancestors
    conflicts_to_remove = set()
    for c in conflicts:
        n, n2 = c
        if g.has_node(n) and g.has_node(n2):
            # Nodes n and n2 are in conflict
            pred_n = len(dag.ancestors(g, n))
            pred_n2 = len(dag.ancestors(g, n2))

            if pred_n > pred_n2:
                conflict_resolved(g, c, n2, conflicts_to_remove)
            elif pred_n2 > pred_n:
                conflict_resolved(g, c, n, conflicts_to_remove)

    update_conflicts(g, conflicts, conflicts_to_remove)


def resolve_conflicts_step4(g, conflicts, beginning):
    # Step 4: take the one with the more sons
    conflicts_to_remove = set()
    for c in conflicts:
        n, n2 = c
        if g.has_node(n) and g.has_node(n2):
            # Nodes n and n2 are in conflict
            sons_n = len(g.out_edges(n))
            sons_n2 = len(g.out_edges(n2))

            if sons_n > sons_n2:
                conflict_resolved(g, c, n2, conflicts_to_remove)
            elif sons_n2 > sons_n:
                conflict_resolved(g, c, n, conflicts_to_remove)

    update_conflicts(g, conflicts, conflicts_to_remove)


def resolve_conflicts_step5(g, conflicts, beginning):
    # Step 5: take one randomly
    conflicts_to_remove = set()
    for c in conflicts:
        n, n2 = c
        # Nodes n and n2 are in conflict
        r = randrange(2)

        if r == 0:
            conflict_resolved(g, c, n2, conflicts_to_remove)
        else:
            conflict_resolved(g, c, n, conflicts_to_remove)

    update_conflicts(g, conflicts, conflicts_to_remove)


def resolve_conflicts(g, conflicts, beginning):
    resolve_conflicts_step1(g, conflicts, beginning)
    resolve_conflicts_step2(g, conflicts, beginning)
    resolve_conflicts_step3(g, conflicts, beginning)
    # resolve_conflicts_step4(g, conflicts, beginning)
    # resolve_conflicts_step5(g, conflicts, beginning)


def draw_conflicts(g, conflicts):
    for c in conflicts:
        n, n2 = c
        connect_to(g, n2, n, "green")
        connect_to(g, n, n2, "green")


def disas_segment(beginning, end, f, fsize):
    g = nx.MultiDiGraph()
    for a in range(beginning, end):
        inst = disas_at(a, f, fsize)
        # if inst.has_target or inst.addr == beginning:
        make_basic_block(beginning, end, a, g, f, fsize)
    conflicts = compute_conflicts(g)
    resolve_conflicts(g, conflicts, beginning)
    print len(conflicts), "conflicts remain."
    draw_conflicts(g, conflicts)
    return g


def disas_file(virt_offset, f, fsize):
    g = nx.Graph()
    g.add_nodes_from(range(virt_offset, fsize+virt_offset))
    # nx.draw_graphviz(g)
    # nx.write_dot(g, 'file.dot')
    print "blah"


g = disas_segment(0, fsize-1, f, fsize)
nx.draw_graphviz(g)
nx.write_dot(g, 'file.dot')
# nx.draw(g)
# plt.show()
# disas_file(0, f, fsize)

# h = nx.DiGraph()
# bb = BasicBlock(0, 0)
# h.add_node(bb)
# bb.size = 2
# h.add_node(bb)
# h.add_node(bb)
# h.add_node(bb)
# h.add_node(bb)
# nx.draw(h)
# plt.show()

for i in range(fsize):
    print disas_at(i, f, fsize)