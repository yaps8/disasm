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


def disas_at(offset, f, size):
    if offset < size:
        f.seek(offset)
        l = distorm3.Decode(offset, f.read(min(16, size-offset)), distorm3.Decode32Bits)[0]
        return Instruction(l)
    else:
        print "Error in disas_at"


def get_first_block_having(g, inst):
    nodes = g.nodes()
    for b in nodes:
        if b.contains_inst(inst):
            return True, b
    return False, None


def split_block(b, addr, g):
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
    return b2


def connect_to(g, block, b, color="black"):
    g.add_edge(block, b, color=color)


def make_basic_block(beginning, end, addr, g, f, fsize):
    block = BasicBlock(addr)

    while beginning <= addr <= end:
        inst = disas_at(addr, f, fsize)
        (exist, b) = get_first_block_having(g, inst)

        if exist:
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


def conflict_in_subset(conflict, conflicts):
    for c in conflicts:
        if c != conflict and conflict.issubset(c):
            print "subset of conflict detected!"
            return True
    return False


def compute_conflicts(g, beginning, end):
    conflicts = set()

    for a in range(beginning, end):
        conflict = []
        for n in g.nodes():
            if n.addr <= a <= n.addr + n.size - 1:
                conflict.append(n)
        if len(conflict) >= 2:
            conflicts.add(frozenset(conflict))

    conflicts_in_subset = set()
    for c in conflicts:
        if conflict_in_subset(c, conflicts):
            conflicts_in_subset.add(c)

    for c in conflicts_in_subset:
        conflicts.remove(c)

    return conflicts


def conflict_resolved(g, conflict, node_to_remove, conflicts_to_remove):
    if g.has_node(node_to_remove):
        g.remove_node(node_to_remove)
    conflicts_to_remove.add(conflict)


def update_conflicts(g, conflicts, non_conflicts=None):
    if non_conflicts is None:
        non_conflicts = set()

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

    conflicts_to_remove.clear()
    conflicts_to_add.clear()

    # Splitting conflicts that have elements no longer in conflicts:
    for nc in non_conflicts:
        for c in conflicts:
            inter = c.intersection(nc)
            if len(inter) >= 2:
                for n in inter:
                    l = []
                    for nn in c:
                        if n != nn:
                            l.append(nn)
                    conflicts_to_add(frozenset(l))
                conflicts_to_remove(c)

    for c in conflicts_to_remove:
        conflicts.remove(c)
    for c in conflicts_to_add:
        conflicts.add(c)



def remove_nodes(g, nodes):
    count = 0
    for n in nodes:
        if g.has_node(n):
            g.remove_node(n)
            count += 1
    return count


def all_reachable_from_set(nodes, g):
    succ = set()
    for n in nodes:
        succ.add(n)
        for e in g.out_edges(n):
            u, v = e
            succ.add(v)
    return succ


def resolve_conflicts_step1(g, conflicts, beginning):
    # Step 1: reachable from pe vs not reachable from pe -> first one
    # En pratique :
    # On prend tous les successeurs du point d'entrée (incluant le pe)
    # En cas de conflit, un successeur est préféré à un non successeur
    # Si aucun ou deux successeurs : on garde les deux
    nodes_to_remove = set()
    non_conflict = set()
    for n in g.nodes():
        if n.addr == beginning:
            succ = g.successors(n)
            succ.append(n)
            break
    for c in conflicts:
        l = []
        # print "solving", set_to_str(c)
        set_from_succ = set()
        set_not_from_succ = set()
        for n in c:
            if n in succ:
                set_from_succ.add(n)
            elif n not in succ:
                set_not_from_succ.add(n)
        succ = all_reachable_from_set(set_from_succ, g)
        if set_from_succ:
            # print "removing", set_to_str(set_not_from_succ)
            for n in set_not_from_succ:
                nodes_to_remove.add(n)
            for n in succ.intersection(set_from_succ):
                l.append(n)

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


def remove_conflicts_from_graph(g, n, conflicts):
    h = soft_graph_copy(g)
    in_conflict = set()
    for c in conflicts:
        if n in c:
            for n2 in c:
                if n2 != n:
                    in_conflict.add(n2)
    succ = dag.descendants(g, n)
    for n2 in in_conflict:
        # print "removing!!", n2
        if n2 not in succ:
            h.remove_node(n2)
    return h


def resolve_conflicts_step3(g, conflicts, beginning):
    # Step 3: take the one with the more ancestors
    nodes_to_remove = set()
    non_conflict = set()
    n_ancestors = dict()
    for c in conflicts:
        last_n_a = -1
        to_keep_succ = set()
        # print "resolving", set_to_str(c)
        for n in c:
            if not n in n_ancestors:
                h = remove_conflicts_from_graph(g, n, conflicts)
                n_ancestors[n] = len(dag.ancestors(h, n))
            n_a = n_ancestors[n]
            if n_a > last_n_a:
                last_n_a = n_a
                for node in dag.descendants(g, n):
                    to_keep_succ.add(node)
                to_keep_succ.add(n)
        l = []
        for n in c:
            n_a = n_ancestors[n]
            if n_a < last_n_a:
                # print "removing", str(hex(int(n.addr)))
                if n not in to_keep_succ:
                    nodes_to_remove.add(n)
                else:
                    l.append(n)

        non_conflict.add(frozenset(l))

    n_removed = remove_nodes(g, nodes_to_remove)
    # update_conflicts(g, conflicts, non_conflict)
    update_conflicts(g, conflicts)
    return n_removed


def resolve_conflicts_step4(g, conflicts, beginning):
    # Step 4: take the one with the more sons
    nodes_to_remove = set()
    n_ancestors = dict()
    for c in conflicts:
        last_n_a = -1
        # print "resolving", set_to_str(c)
        for n in c:
            if not n in n_ancestors:
                h = remove_conflicts_from_graph(g, n, conflicts)
                n_ancestors[n] = len(h.out_edges(n))
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


def resolve_conflicts_step5(g, conflicts, beginning):
    # Step 5: take one randomly
    nodes_to_remove = set()
    for c in conflicts:
        r = randrange(len(c))
        i = 0
        print "c", set_to_str(c), len(c), r
        for n in c:
            if i != r:
                nodes_to_remove.add(n)
            i += 1
        break

    n_removed = remove_nodes(g, nodes_to_remove)
    update_conflicts(g, conflicts)
    return n_removed


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
    print_conflicts(conflicts)
    print "Solving", len(conflicts), "conflicts."
    iterate_step(resolve_conflicts_step1, g, conflicts, beginning)
    print "After step 1,", len(conflicts), "conflicts remain."
    iterate_step(resolve_conflicts_step2, g, conflicts, beginning)
    print "After step 2,", len(conflicts), "conflicts remain."
    # iterate_step(resolve_conflicts_step3, g, conflicts, beginning)
    # print "After step 3,", len(conflicts), "conflicts remain."
    # iterate_step(resolve_conflicts_step4, g, conflicts, beginning)
    # print "After step 4,", len(conflicts), "conflicts remain."
    # iterate_step(resolve_conflicts_step5, g, conflicts, beginning)
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


def disas_file(f, fsize):
    return disas_segment(0, fsize - 1, f, fsize)


# g = disas_segment(0, fsize-1, f, fsize)
g = disas_file(f, fsize)
nx.draw_graphviz(g)
nx.write_dot(g, 'file.dot')