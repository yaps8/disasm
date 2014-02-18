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
        s = ""
        for i in self.insts:
            inst = disas_at(i, f, fsize)
            s += str(hex(int(inst.addr))) + " " + inst.desc + "\\n"
        return s

    def insts_to_hex(self):
        return [hex(int(i)) for i in self.insts]

    def __str__(self):
        return "[" + str(hex(int(self.addr))) + " -> " + str(hex(int(self.addr+self.size-1))) \
               + "] (" + str(hex(int(self.size))) + ")" + " \\n " + self.insts_to_str()

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


def compute_conflicts(g, beginning, end):
    conflicts = set()
    # done = set()

    for a in range(beginning, end):
        conflict = []
        for n in g.nodes():
            if n.addr <= a <= n.addr + n.size - 1:
                conflict.append(n)
        if len(conflict) >= 2:
            conflicts.add(frozenset(conflict))

    return conflicts
    #
    # for n in g.nodes():
    #     for n2 in g.nodes():
    #         if (not frozenset([n.addr, n2.addr]) in done) and n != n2:
    #             if n.addr <= n2.addr <= n.addr + n.size - 1 or n.addr <= n2.addr + n2.size - 1 <= n.addr + n.size - 1:
    #                 done.add(frozenset([n.addr, n2.addr]))
    #                 conflicts.add((n, n2))
    # return conflicts


def conflict_resolved(g, conflict, node_to_remove, conflicts_to_remove):
    if g.has_node(node_to_remove):
        g.remove_node(node_to_remove)
    conflicts_to_remove.add(conflict)


def update_conflicts(g, conflicts):
    conflicts_to_remove = set()
    conflicts_to_add = set()
    for c in conflicts:
        l = []
        for n in c:
            if g.has_node(n):
                l.append(n)
        if len(l) != len(c):
            conflicts_to_remove.add(c)
            if len(l) >= 2:
                conflicts_to_add.add(frozenset(l))

    for c in conflicts_to_remove:
        conflicts.remove(c)
    for c in conflicts_to_add:
        conflicts.add(c)


# def resolve_successors_from(g, conflicts, node):
#     conflicts_to_remove = set()
#     for c in conflicts:
#         n, n2 = c
#         # Nodes n and n2 are in conflict
#         if n is node:
#             conflict_resolved(g, c, n2, conflicts_to_remove)
#         elif n2 is node:
#             conflict_resolved(g, c, n, conflicts_to_remove)
#
#     update_conflicts(g, conflicts, conflicts_to_remove)
#     for edge in g.out_edges(node):
#         u, v = edge
#         resolve_successors_from(v)


def remove_nodes(g, nodes):
    count = 0
    for n in nodes:
        if g.has_node(n):
            g.remove_node(n)
            count += 1
    return count


def resolve_conflicts_step1(g, conflicts, beginning):
    # Step 1: reachable from pe vs not reachable from pe -> first one
    # En pratique :
    # On prend tous les successeurs du point d'entrée (incluant le pe)
    # En cas de conflit, un successeur est préféré à un non successeur
    # Si aucun ou deux successeurs : on garde les deux
    nodes_to_remove = set()
    for n in g.nodes():
        if n.addr == beginning:
            succ = g.successors(n)
            succ.append(n)
            break
    for c in conflicts:
        # print "solving", set_to_str(c)
        set_from_succ = set()
        set_not_from_succ = set()
        for n in c:
            if n in succ:
                set_from_succ.add(n)
            elif n not in succ:
                set_not_from_succ.add(n)

        if set_from_succ:
            # print "removing", set_to_str(set_not_from_succ)
            for n in set_not_from_succ:
                nodes_to_remove.add(n)
        # print c
        # n, n2 = c
        # # Nodes n and n2 are in conflict
        # if n in succ and n2 not in succ:
        #     nodes_to_remove.add(n2)
        # elif n2 in succ and n not in succ:
        #     nodes_to_remove.add(n)

    n_removed = remove_nodes(g, nodes_to_remove)
    update_conflicts(g, conflicts)
    return n_removed


def resolve_conflicts_step2(g, conflicts, beginning):
    # Step 2: remove common ancestors of nodes in conflict
    nodes_to_remove = set()
    couples_done = set()
    ancestors = dict()
    for c in conflicts:
        for n in c:
            for n2 in c:
                if n != n2 and frozenset([n, n2]) not in couples_done:
                    if n in ancestors:
                        a_n = ancestors[n]
                    else:
                        ancestors[n] = dag.ancestors(g, n)
                        a_n = ancestors[n]
                    if n2 in ancestors:
                        a_n2 = ancestors[n2]
                    else:
                        ancestors[n2] = dag.ancestors(g, n2)
                        a_n2 = ancestors[n2]
                    inter = a_n.intersection(a_n2)

                    for nn in inter:
                        nodes_to_remove.add(nn)
                    couples_done.add(frozenset([n, n2]))

    n_removed = remove_nodes(g, nodes_to_remove)
    update_conflicts(g, conflicts)
    return n_removed


def soft_graph_copy(g):
    h = nx.MultiDiGraph()
    for n in g.nodes():
        h.add_node(n)
    for e in g.edges():
        u, v = e
        h.add_edge(u, v)
    return h


def ancestors_without_conflicts(g, n, conflicts):
    h = soft_graph_copy(g)
    in_conflict = set()
    for c in conflicts:
        if n in c:
            for n2 in c:
                if n2 != n:
                    in_conflict.add(n2)
    for n2 in in_conflict:
        # print "removing!!", n2
        h.remove_node(n2)
    return dag.ancestors(h, n)


def resolve_conflicts_step3(g, conflicts, beginning):
    # Step 3: take the one with the more ancestors
    nodes_to_remove = set()
    n_ancestors = dict()
    for c in conflicts:
        last_n_a = -1
        # print "resolving", set_to_str(c)
        for n in c:
            if not n in n_ancestors:
                n_ancestors[n] = len(ancestors_without_conflicts(g, n, conflicts))
            n_a = n_ancestors[n]
            if n_a > last_n_a:
                last_n_a = n_a
        for n in c:
            n_a = n_ancestors[n]
            if n_a < last_n_a:
                # print "removing", str(hex(int(n.addr)))
                nodes_to_remove.add(n)

    n_removed = remove_nodes(g, nodes_to_remove)
    update_conflicts(g, conflicts)
    return n_removed


def sons_without_conflicts(g, n, conflicts):
    h = soft_graph_copy(g)
    in_conflict = set()
    for c in conflicts:
        if n in c:
            for n2 in c:
                if n2 != n:
                    in_conflict.add(n2)
    for n2 in in_conflict:
        h.remove_node(n2)

    return h.out_edges(n)


def resolve_conflicts_step4(g, conflicts, beginning):
    # Step 4: take the one with the more sons
    nodes_to_remove = set()
    n_ancestors = dict()
    for c in conflicts:
        last_n_a = -1
        # print "resolving", set_to_str(c)
        for n in c:
            if not n in n_ancestors:
                n_ancestors[n] = len(sons_without_conflicts(g, n, conflicts))
            n_a = n_ancestors[n]
            if n_a > last_n_a:
                last_n_a = n_a
        for n in c:
            n_a = n_ancestors[n]
            if n_a < last_n_a:
                # print "removing", str(hex(int(n.addr)))
                nodes_to_remove.add(n)

    n_removed = remove_nodes(g, nodes_to_remove)
    update_conflicts(g, conflicts)
    return n_removed


def resolve_conflicts_step5(g, conflicts):
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


def iterate_step(fun, g, conflicts, beginning):
    while True:
        n_removed = fun(g, conflicts, beginning)
        print fun, "removed", n_removed, "nodes."
        if n_removed == 0:
            break


def set_to_str(c):
    s = ""
    for n in c:
        s += str(hex(int(n.addr))) + " "
    return s


def print_conflicts(conflicts):
    print "Conflicts:"
    s = ""
    for c in conflicts:
        s += set_to_str(c) + "\n"
    print s


def resolve_conflicts(g, conflicts, beginning):
    # print_conflicts(conflicts)
    print "Solving", len(conflicts), "conflicts."
    iterate_step(resolve_conflicts_step1, g, conflicts, beginning)
    print "After step 1,", len(conflicts), "conflicts remain."
    iterate_step(resolve_conflicts_step2, g, conflicts, beginning)
    print "After step 2,", len(conflicts), "conflicts remain."
    iterate_step(resolve_conflicts_step3, g, conflicts, beginning)
    print "After step 3,", len(conflicts), "conflicts remain."
    iterate_step(resolve_conflicts_step4, g, conflicts, beginning)
    print "After step 4,", len(conflicts), "conflicts remain."
    # resolve_conflicts_step5(g, conflicts)
    # print "After step 5,", len(conflicts), "conflicts remain."


def draw_conflicts(g, conflicts):
    draw = set()
    for c in conflicts:
        for n1 in c:
            for n2 in c:
                if n1 != n2:
                    draw.add(frozenset([n1, n2]))

    for d in draw:
        n1, n2 = d
        connect_to(g, n1, n2, "green")
        # n, n2 = c
        # connect_to(g, n2, n, "green")
        # connect_to(g, n, n2, "green")


def disas_segment(beginning, end, f, fsize):
    g = nx.MultiDiGraph()
    for a in range(beginning, end):
        inst = disas_at(a, f, fsize)
        if inst.has_target or inst.addr == beginning:
            make_basic_block(beginning, end, a, g, f, fsize)
    conflicts = compute_conflicts(g, beginning, end)
    resolve_conflicts(g, conflicts, beginning)
    print len(conflicts), "conflicts remain."
    draw_conflicts(g, conflicts)
    return g


# def disas_file(virt_offset, f, fsize):
#     g = nx.Graph()
#     g.add_nodes_from(range(virt_offset, fsize+virt_offset))
#     # nx.draw_graphviz(g)
#     # nx.write_dot(g, 'file.dot')
#     print "blah"


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

# for i in range(fsize):
#     print disas_at(i, f, fsize)