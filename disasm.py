#!/usr/bin/python2.7
# coding: utf-8
from _socket import gaierror

import sys
import os
import distorm3
import networkx as nx
from networkx import dag
from random import randrange
from r2 import r_core
# from  import Enum
# import matplotlib.pyplot as plt
# import pydot

useRadare = True


def dict_op():
    opcodes = dict()
    total = 0
    for line in open('traces/opcodes'):
        total += 1
        opc = line.lower()[0:-1]
        if opcodes.has_key(opc):
            opcodes[opc] += 1
        else:
            opcodes[opc] = 1

    op_prop = dict()
    for op in opcodes.keys():
        ratio = 1000 * (float(opcodes[op]) / float(total))
        op_prop[op] = ratio
        # print opcodes[op], "(", str(ratio)[0:5], "%%)", op
    return op_prop


def hi(a):
    return hex(int(a))


class Instruction:
    def __init__(self, addr, size, desc, is_call, has_target, target, is_jcc, disas_seq):
        self.addr = addr
        self.size = size
        self.desc = desc
        self.is_call = is_call
        self.has_target = has_target
        self.target = target
        self.is_jcc = is_jcc
        self.disas_seq = disas_seq

    @staticmethod
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

    @staticmethod
    def inst_from_distorm(d_inst):
        addr = d_inst[0]
        size = d_inst[1]
        desc = d_inst[2].lower()
        i, t, jcc, call = Instruction.target(d_inst[2].lower())
        is_call = call
        has_target = i
        target = t
        is_jcc = jcc
        return Instruction(addr, size, desc, is_call, has_target, target, is_jcc, True)

    def __str__(self):
        s = str(hex(int(self.addr))) + ", " + str(hex(int(self.size))) + ", " + self.desc
        if self.has_target:
            s += ", target: " + hex(int(self.target))
        if self.is_jcc:
            s += ", is_jcc"
        if not self.disas_seq:
            s += ", not disas_seq"
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
            inst = disas_at_r2(i, virtual_offset, beginning, end, f)
            if inst.desc is None:
                print "None"
            s += str(hex(int(inst.addr))) + " " + inst.desc + "\\n"
        return s

    def insts_to_hex(self):
        return [hex(int(i)) for i in self.insts]

    def __str__(self):
        return "BB [" + str(hex(int(self.addr))) + " -> " + str(hex(int(self.addr+self.size-1))) \
               + "] (" + str(hex(int(self.size))) + ")" + "\\n" + self.insts_to_str()


def trace_from_path(path):
    i = 0
    for line in open(path):
        i += 1
        if "#" not in line:
            key = int(line, 16)
            if key in trace:
                trace[key].append(i)
            else:
                trace[key] = [i]
    return trace


if len(sys.argv) > 1:
    path = sys.argv[1]
else:
    # path = "/home/aurelien/trace/telock99-hostname.bin/telock99-hostname.bin.exe.snapshot2"
    path = "ex.bin"
f = open(path, "rb")
fsize = os.path.getsize(path)

if len(sys.argv) > 3:
    beginning = int(sys.argv[2], 16)
    end = int(sys.argv[3], 16)

else:
    beginning = 0
    end = fsize - 1

if len(sys.argv) > 4:
    virtual_offset = int(sys.argv[4], 16)
else:
    virtual_offset = 0

trace = dict()
if len(sys.argv) > 5:
    trace_from_path(sys.argv[5])

rc = r_core.RCore()
# rc.assembler.set_syntax(1)  # Intel syntax
rc.config.set_i('asm.arch', 32)
rc.assembler.set_bits(32)
rc.anal.set_bits(32)
rc.file_open(path, 0, 0)
rc.bin_load("", 0)

op_chance_1000 = dict_op()

call_blacklist = set()
call_blacklist.add("call dword [edi-0x7d]")
call_blacklist.add("call 0xc10d7257")
call_blacklist.add("call dword [eax-0x3d7cfd75]")
call_blacklist.add("call far dword [esi-0x77]")
call_blacklist.add("call dword [esi+0x5494]")
call_blacklist.add("call dword [esi+0x5498]")
call_blacklist.add("call dword [esi+0x54a8]")
call_blacklist.add("call ebp")


def disas_at_distorm(addr, virtual_offset, beginning, end, f):
    if beginning <= addr <= end:
        f.seek(addr)
        l = distorm3.Decode(addr, f.read(min(16, end-addr)), distorm3.Decode32Bits)[0]
        l[0] += virtual_offset
        return Instruction.inst_from_distorm(l)
    else:
        print "Error in disas_at"


class OpType:
    R_ANAL_OP_TYPE_COND  = int(0x80000000)
    R_ANAL_OP_TYPE_REP   = int(0x40000000) # /* repeats next instruction N times */
    R_ANAL_OP_TYPE_NULL  = 0
    R_ANAL_OP_TYPE_JMP   = 1 # /* mandatory jump */
    R_ANAL_OP_TYPE_UJMP  = 2 # /* unknown jump (register or so) */
    R_ANAL_OP_TYPE_CJMP  = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_JMP # /* conditional jump */
    R_ANAL_OP_TYPE_CALL  = 3  # /* call to subroutine (branch+link) */
    R_ANAL_OP_TYPE_UCALL = 4  # /* unknown call (register or so) */
    R_ANAL_OP_TYPE_RET   = 5  # /* returns from subrutine */
    R_ANAL_OP_TYPE_CRET  = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_RET # /* returns from subrutine */
    R_ANAL_OP_TYPE_ILL   = 6  # /* illegal instruction // trap */
    R_ANAL_OP_TYPE_UNK   = 7  # /* unknown opcode type */
    R_ANAL_OP_TYPE_NOP   = 8  # /* does nothing */
    R_ANAL_OP_TYPE_MOV   = 9  # /* register move */
    R_ANAL_OP_TYPE_TRAP  = 10  # /* it's a trap! */
    R_ANAL_OP_TYPE_SWI   = 11  # /* syscall, software interrupt */
    R_ANAL_OP_TYPE_UPUSH = 12  # /* unknown push of data into stack */
    R_ANAL_OP_TYPE_PUSH  = 13  # /* push value into stack */
    R_ANAL_OP_TYPE_POP   = 14  # /* pop value from stack to register */
    R_ANAL_OP_TYPE_CMP   = 15  # /* copmpare something */
    R_ANAL_OP_TYPE_ADD   = 16
    R_ANAL_OP_TYPE_SUB   = 17
    R_ANAL_OP_TYPE_IO    = 18
    R_ANAL_OP_TYPE_MUL   = 19
    R_ANAL_OP_TYPE_DIV   = 20
    R_ANAL_OP_TYPE_SHR   = 21
    R_ANAL_OP_TYPE_SHL   = 22
    R_ANAL_OP_TYPE_SAL   = 23
    R_ANAL_OP_TYPE_SAR   = 24
    R_ANAL_OP_TYPE_OR    = 25
    R_ANAL_OP_TYPE_AND   = 26
    R_ANAL_OP_TYPE_XOR   = 27
    R_ANAL_OP_TYPE_NOT   = 28
    R_ANAL_OP_TYPE_STORE = 29  # /* store from register to memory */
    R_ANAL_OP_TYPE_LOAD  = 30  # /* load from memory to register */
    R_ANAL_OP_TYPE_LEA   = 31
    R_ANAL_OP_TYPE_LEAVE = 32
    R_ANAL_OP_TYPE_ROR   = 33
    R_ANAL_OP_TYPE_ROL   = 34
    R_ANAL_OP_TYPE_XCHG  = 35
    R_ANAL_OP_TYPE_MOD   = 36
    R_ANAL_OP_TYPE_SWITCH = 37


def disas_at_r2(addr, virtual_offset, beginning, end, f):
    # print "disas at", hex(int(offset)), "size:", hex(int(size))
    # print "beg", hi(beginning)
    # print "end", hi(end)
    # print "virt", hi(virtual_offset)
    # print "addr", hi(addr)

    if beginning <= addr <= end:
        # print "anal"
        anal_op = rc.op_anal(addr)
        # print "anal done"
        addr = int(anal_op.addr) + virtual_offset
        size = abs(int(anal_op.size))
        desc = str(rc.op_str(addr))
        optype = anal_op.type & 0xff
        disas_seq = True
        # print "optype:", anal_op.type,"ptr:" , anal_op.ptr, "family:", anal_op.family, "fail:", anal_op.fail
        if optype == OpType.R_ANAL_OP_TYPE_JMP or (optype == OpType.R_ANAL_OP_TYPE_CALL and desc not in call_blacklist):
            # print int(anal_op.jump)
            if optype == OpType.R_ANAL_OP_TYPE_JMP:
                disas_seq = False
            has_target = True
            target = int(anal_op.jump)
            # print "target:", target
        else:
            has_target = False
            target = None

        # if optype == OpType.R_ANAL_OP_TYPE_UCALL or (optype == OpType.R_ANAL_OP_TYPE_CALL and desc in call_blacklist) or optype == OpType.R_ANAL_OP_TYPE_UJMP:
        if optype == OpType.R_ANAL_OP_TYPE_UJMP:
            disas_seq = False

        # print "type", anal_op.type
        # print "t & 0xff", anal_op.type & 0xff
        # print "abs(t >> 31)", abs(anal_op.type >> 31)

        conditional = abs(anal_op.type >> 31)
        if conditional != 0:
            is_jcc = True
        else:
            is_jcc = False

        is_call = False
        if optype == OpType.R_ANAL_OP_TYPE_CALL:
            is_call = True

        if desc is None and optype == OpType.R_ANAL_OP_TYPE_ILL:
            desc = "(illegal)"

        i = Instruction(addr, size, desc, is_call, has_target, target, is_jcc, disas_seq)
        if i is None:
            print "NONE"
        # print i
        return i
    else:
        print "Error in disas_at_r2"


def disas_at(addr, virtual_offset, beginning, end, f):
    if useRadare:
        return disas_at_r2(addr, virtual_offset, beginning, end, f)
    else:
        return disas_at_distorm(addr, virtual_offset, beginning, end, f)


def get_first_block_having(g, inst):
    nodes = g.nodes()
    for b in nodes:
        if b.contains_inst(inst):
            return True, b
    return False, None


def split_block(b, addr, g):
    b2 = BasicBlock(addr)
    b2.insts = [x for x in b.insts if x >= addr]
    b2.size = int(b.addr - addr + b.size)
    g.add_node(b2)
    for e in g.out_edges(b, data=True):
        u, v, d = e
        connect_to(g, b2, v, d['color'])
        g.remove_edge(u, v)
    connect_to(g, b, b2)
    b.size = int(addr - b.addr)
    b.insts = [x for x in b.insts if x < addr]
    return b2


def split_all_blocks(g):
    c = 1
    while c != 0:
        c = 0
        for n in g.nodes():
            if len(n.insts) > 1:
                c += 1
                split_block(n, n.insts[1], g)


def connect_to(g, block, b, color="black"):
    # print "connecting", "["+hi(block.addr), hi(block.size+block.addr-1)+"]", "["+hi(b.addr), hi(b.size+b.addr-1)+"]"
    g.add_edge(block, b, color=color)


def addr_to_block(g, addr):
    for n in g.nodes():
        if addr in n.insts:
            return n


def make_basic_block(beginning, end, virtual_offset, addr, g, f, fsize):
    block = BasicBlock(addr)

    while beginning <= addr <= end:
        inst = disas_at_r2(addr, virtual_offset, beginning, end, f)
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
                    b = make_basic_block(beginning, end, virtual_offset, target, g, f, fsize)
                    block = addr_to_block(g, addr)
                    b = addr_to_block(g, target)
                    connect_to(g, block, b, "red")

                if inst.is_jcc or inst.is_call:
                    b = make_basic_block(beginning, end, virtual_offset, addr + inst.size, g, f, fsize)
                    block = addr_to_block(g, addr)
                    b = addr_to_block(g, addr + inst.size)
                    connect_to(g, block, b)

                return block
            else:
                if not inst.disas_seq:
                    return block
                else:
                    addr += inst.size
    return block


def conflict_in_subset(conflict, conflicts):
    for c in conflicts:
        if c != conflict and conflict.issubset(c):
            # print "subset of conflict detected!"
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
    # TODO : WTF ?
    nodes_to_remove = set()
    non_conflict = set()
    for n in g.nodes():
        if n.addr == beginning:
            succ = g.successors(n)
            succ.append(n)
            break
    # for nn in succ:
    #     print nn, id(nn)
    # print set_to_str(succ)
    # print id(n)
    # print
    for c in conflicts:
        l = []
        # print "solving", set_to_str(c)
        set_from_succ = set()
        set_not_from_succ = set()
        for n in c:
            # print "n:", n, id(n)
            # print "ids:"
            # for nn in succ:
            #     print id(nn)
            # print "/ids"
            if n in succ:
                set_from_succ.add(n)
            elif n not in succ:
                set_not_from_succ.add(n)
        # print "conflit:", set_to_str(c)
        # print "succ:", set_to_str(set_from_succ)
        # print "not succ:", set_to_str(set_not_from_succ)
        # print ""
        all_succ = all_reachable_from_set(set_from_succ, g)
        if set_from_succ:
            # print "removing", set_to_str(set_not_from_succ)
            for n in set_not_from_succ:
                nodes_to_remove.add(n)
            for n in all_succ.intersection(set_from_succ):
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
    # iterate_step(resolve_conflicts_step2, g, conflicts, beginning)
    # print "After step 2,", len(conflicts), "conflicts remain."
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


def remove_bad_prop(g):
    nodes_to_remove = set()
    for n in g.nodes():
        inst = disas_at(n.insts[0], f, fsize)
        op0 = inst.desc.split(" ")[0]
        if not op_chance_1000.has_key(op0):
            print "not", op0
            p = 0
        else:
            p = op_chance_1000[op0]
            print "has", op0, p

        if p == 0:
            nodes_to_remove.add(n)
            color = "black"
        elif p < 0.1:
            nodes_to_remove.add(n)
            color = "brown"
        elif p < 1:
            nodes_to_remove.add(n)
            color = "red"
        elif p < 5:
            color = "pink"
        else:
            color = "blue"

    remove_nodes(g, nodes_to_remove)


def disas_segment(beginning, end, virtual_offset, f):
    g = nx.MultiDiGraph()
    for a in range(beginning, end):
        inst = disas_at(a, virtual_offset, beginning, end, f)
        # if inst.has_target or inst.addr == beginning:
        # print hi(inst.addr), hi(virtual_offset)
        # if inst.addr == beginning: #or inst.addr == 0x4:
        make_basic_block(beginning, end, virtual_offset, a, g, f, fsize)
    conflicts = compute_conflicts(g, beginning, end)
    # resolve_conflicts(g, conflicts, beginning)
    print len(conflicts), "conflicts remain."
    print_conflicts(conflicts)
    draw_conflicts(g, conflicts)
    return g


def disas_file(beginning, end, virtual_offset, f):
    return disas_segment(beginning, end, virtual_offset, f)
    # return disas_segment(0x6e5b, fsize-1, f, fsize)
    # return disas_segment(0x6e5b, 0x6e8a, f, fsize)


def print_graph_to_file(path, virtual_offset, g, ep_addr):
    f = open(path, 'wb')
    f.write("digraph G {\n")
    f.write("labeljust=r\n")
    for n in g.nodes():
        inst = disas_at(n.insts[0], virtual_offset, beginning, end, f)
        op0 = inst.desc.split(" ")[0]
        if not op0 in op_chance_1000:
            print "not", op0
            p = 0
        else:
            p = op_chance_1000[op0]
            print "has", op0, p

        if p == 0:
            color = "\"#000000\""
        elif p < 0.1:
            color = "\"#000022\""
        elif p < 1:
            color = "\"#000055\""
        elif p < 5:
            color = "\"#000077\""
        else:
            color = "\"#0000bb\""

        if n.addr in trace:
            ordres = str(trace[n.addr])
            # color = "pink"
            shape = "octagon"
        else:
            ordres = ""
            shape = "box"

        if n.addr == ep_addr:
            f.write("\"" + hex(int(n.addr)) + "\"" + " [label=\"" + str(n).replace("\\n", "\l") + "\", shape=box, "
                    "style=\"bold, filled\", fillcolor=\"orange\"]\n")
        else:
            f.write("\"" + hex(int(n.addr)) + "\"" + " [labeljust=r,label=\"" + ordres + ", " + str(n).replace("\\n", "\l") +
                    "\", shape=" + shape + ", style=\"filled\", fillcolor=" + color + "]\n")

    for e in g.edges(data=True):
        u, v, d = e
        if d['color'] == "green":
            f.write("\"" + hex(int(u.addr)) + "\"" + " -> " + "\"" + hex(int(v.addr)) + "\" [style=dotted,arrowhead=none,color=" + d['color'] + "]\n")
        else:
            f.write("\"" + hex(int(u.addr)) + "\"" + " -> " + "\"" + hex(int(v.addr)) + "\" [color=" + d['color'] + "]\n")
    f.write("}")

# g = nx.MultiDiGraph()
# g.add_node(2, "e")
# g.add_node(3, "g")
# g.add_node(4, "m")
g = disas_file(beginning, end, virtual_offset, f)
split_all_blocks(g)
print_graph_to_file("file.dot", virtual_offset, g, beginning)

#
# nx.draw_graphviz(g)
# nx.write_dot(g, 'file.dot')

# print disas_at_r2(0x6e6d, f, fsize)
#
# for a in range(fsize):
#     i1 = disas_at_distorm(a, virtual_offset, beginning, end, f)
#     i2 = disas_at_r2(a, virtual_offset, beginning, end, f)
#     print str(hex(int(a)))
#     print "Distorm:", i1
#     print "Radare2:", i2
#     print ""