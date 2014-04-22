#!/usr/bin/python2.7
# coding: utf-8

import sys
import os
import networkx as nx
import bisect
from networkx import dag
from random import randrange
from r2 import r_core
import numpy
import threading


useRadare = True
sys.setrecursionlimit(1500000)
threading.stack_size(67108864)

'''
Colors:
    Nodes:
        Orange -> entrypoint (into trace)
        Blue -> exitpoint (from trace)
        Pink -> node in trace
        White -> node not in trace (static analysis)
    Edges:
        Color:
            Red -> Jump target
            Black -> Next instruction
        Shape:
            Dashed -> From static analysis only
            Solid -> From trace only
            Bold -> Both
    Conflicts:
        Black dotted (non directional) edges
'''


'''
Initial CFG from trace (from sub-approx):
    (Done) Disasm all from trace (sons of trace are legitimate), stop at last trace instruction
        With restrictions: Classify calls from trace
    (Done) Remove error paths (None)
    (Done) Mark probabity of paths (n-grams)
    (TODO) Remove very improbabable paths
Optimal CFG:
    In-between...
Static CFG (from over-approx): (TODO)
    Disasm all addresses from the binary file
    Take long path conflicting with iCFG
    Take very probable paths
    Take very connected graphs (?)
'''


def dict_op():
    opcodes = dict()
    total = 0
    for line in open('opcodes'):
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
    def __init__(self, addr, size, desc, is_call, has_target, target, is_jcc, disas_seq, is_none, is_int):
        self.addr = addr
        self.size = size
        self.desc = desc
        self.is_call = is_call
        self.has_target = has_target
        self.target = target
        self.is_jcc = is_jcc
        self.disas_seq = disas_seq
        self.is_none = is_none
        self.is_int = is_int
        self.prob = None

    def __str__(self):
        s = str(hex(int(self.addr))) + ": " + str(hex(int(self.size))) + ", " + self.desc
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
        self.insts_int = []
        self.insts = []
        self.head_is_none = False

    def add_inst(self, inst):
        # check that the inst is just following the block
        if inst.addr != self.addr + self.size:
            print "Error in add_inst_to_block: inst does not follow block.", hi(inst.addr), hi(self.addr), self.size
        else:
            self.size += inst.size
            self.insts_int.append(inst.addr)
            self.insts.append(inst)

    def contains_inst(self, inst):
        return inst.addr in self.insts_int

    def insts_to_str(self):
        s = ""
        skip = set()
        for i in range(len(self.insts_int)):
            if i not in skip:
                inst = self.insts[i]
                p = inst.prob
                if inst.desc is None:
                    print "None"

                count = 1
                for j in range(i + 1, len(self.insts_int)):
                    i_j = self.insts[j]
                    if i_j.desc == inst.desc:
                        skip.add(j)
                        count += 1
                    else:
                        break
                if count == 1:
                    s_count = ""
                else:
                    s_count = " (x" + str(count) + ")"

                s += str(hex(int(inst.addr))) + " " + inst.desc + " (P=" + str(p) + ")" + s_count + "\\n"
        return s

    def insts_to_hex(self):
        return [hex(int(i)) for i in self.insts_int]

    def __str__(self):
        s = "BB [" + str(hex(int(self.addr))) + " -> " + str(hex(int(self.addr+self.size-1))) \
                   + "](" + str(hex(int(self.size))) + ")\\n"
        s += self.insts_to_str()

        return s


def trace_from_path(lines):
    i = 0
    trace_dict = dict()
    trace_list = []
    for line in lines:
        i += 1
        if "#" not in line:
            key = int(line, 16)
            if beginning <= key <= end:
                trace_list.append(key)
                if key in trace_dict:
                    trace_dict[key].append(i)
                else:
                    trace_dict[key] = [i]
    if len(trace_list) == 0:
        return None, None, trace_list, trace_dict
    elif len(trace_list) == 1:
        return trace_list[0], trace_list[0], trace_list, trace_dict
    else:
        return trace_list[0], trace_list[-1], trace_list, trace_dict


def classify_calls(lines):
    calls = dict() # addr -> +1 addr
    return_addr = set()
    opcodes_trace = []
    for i in range(len(lines)):
        l = lines[i]
        if "_" in l:
            a = l.split()
            if len(a) >= 4:
                size = int(a[1][1:3], 16)
                opcodes_trace.append(a[3].lower())
                if a[3] == "CALL":
                    wave, addr = a[0].split("_")
                    addr = int(addr, 16)
                    if addr not in calls.keys():
                        ret_addr = addr + size
                        calls[addr] = ret_addr

                        if i + 1 < len(lines):
                            next_line = lines[i+1]
                            a = next_line.split()
                            next_wave, next_addr = a[0].split("_")
                            next_addr = int(next_addr, 16)
                            return_addr.add(next_addr)
                elif a[3] == "RET":
                    if i + 1 < len(lines):
                        next_line = lines[i+1]
                        a = next_line.split()
                        next_wave, next_addr = a[0].split("_")
                        next_addr = int(next_addr, 16)
                        return_addr.add(next_addr)

    for a in calls.keys():
        if calls[a] in return_addr:
            true_call.add(a)
        else:
            false_call.add(a)
    return true_call, false_call, opcodes_trace


if len(sys.argv) <= 1 or sys.argv[1] == "-h" or sys.argv[1] == "--help":
    usage = "python disasm.py (first_addr) (last_addr) (offset) (entrypoint) (trace_list) (trace_detailled) " \
            "(bin/dump) (n-gram.prob) (usatrace/displaytrace)"
    print "Usage:", usage
    print "See examples in examples file."
    exit()
else:
    path = sys.argv[1]

f = open(path, "rb")
fsize = os.path.getsize(path)

if len(sys.argv) > 2 and sys.argv[2] != "/":
    beginning = int(sys.argv[2], 16)
else:
    beginning = 0

if len(sys.argv) > 3 and sys.argv[3] != "/":
    end = int(sys.argv[3], 16)
else:
    end = beginning + fsize - 1

if len(sys.argv) > 4 and sys.argv[4] != "/":
    virtual_offset = int(sys.argv[4], 16)
else:
    virtual_offset = 0

if len(sys.argv) > 5 and sys.argv[5] != "/":
    ep_known = True
    entrypoint = int(sys.argv[5], 16)
else:
    ep_known = False
    entrypoint = beginning


true_call = set()
false_call = set()
opcodes_trace = []
if len(sys.argv) > 7 and sys.argv[7] != "/":
    fichier = open(sys.argv[7], "rb")
    lines = [line.strip() for line in fichier]
    fichier.close()
    true_call, false_call, opcodes_trace = classify_calls(lines)
    print len(true_call) + len(false_call), "calls,", len(true_call), "legitimate,", len(false_call), "obfuscated."

addr_info = dict()

rc = r_core.RCore()
bin = rc.file_open(path, 0, virtual_offset)

if len(sys.argv) > 8 and sys.argv[8] == "dump":
    print "Loading binary dump."
else:
    rc.bin_load("", 0)


if end == 0:
    end = beginning + bin.size

trace_dict = dict()
trace_list = []
trace_first_addr = beginning
trace_last_addr = end
if len(sys.argv) > 6 and sys.argv[6] != "/":
    fichier = open(sys.argv[6], "rb")
    lines = [line.strip() for line in fichier]
    fichier.close()
    trace_first_addr, trace_last_addr, trace_list, trace_dict = trace_from_path(lines)
    if trace_first_addr is not None:
        entrypoint = trace_first_addr

n_n_gram = 3
n_grams = dict()
addr_to_m_gram = dict()


def trace_ngrams(opcodes, n_n_gram):
    m_gram = []
    tuples = set()
    for op in opcodes:
        m_gram.append(op)
        if len(m_gram) == n_n_gram:
            t = tuple(m_gram)
            tuples.add(t)
            m_gram.pop(0)
    return tuples


useTrace = True
if len(sys.argv) > 9 and sys.argv[9] == "displaytrace":
    useTrace = False

rc.config.set_i('asm.arch', 32)
rc.assembler.set_bits(32)
rc.anal.set_bits(32)

reg_set = set()
reg_set.add("eax")
reg_set.add("ebx")
reg_set.add("ecx")
reg_set.add("esi")
reg_set.add("edi")
reg_set.add("ebp")
reg_set.add("eip")


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


def disas_at_r2(addr, beginning, end):
    if addr in addr_info:
        if 'inst' in addr_info[addr]:
            return addr_info[addr]['inst']
    else:
        addr_info[addr] = dict()

    if beginning <= addr <= end:
        anal_op = rc.op_anal(addr)
        addr = int(anal_op.addr)
        size = abs(int(anal_op.size))
        desc = str(rc.op_str(addr))
        optype = anal_op.type & 0xff
        disas_seq = True
        is_call = False
        is_jcc = False
        has_target = False
        target = None
        is_none = False
        is_int = False
        if optype == OpType.R_ANAL_OP_TYPE_CALL:
            for r in reg_set:
                if r in desc:
                    optype = OpType.R_ANAL_OP_TYPE_UCALL
        elif "rep " in desc:
            optype = OpType.R_ANAL_OP_TYPE_REP

        if optype == OpType.R_ANAL_OP_TYPE_JMP:
            conditional = abs(anal_op.type >> 31)
            if conditional != 0:
                is_jcc = True
                disas_seq = True
            else:
                is_jcc = False
                disas_seq = False
            has_target = True
            target = int(anal_op.jump)
        elif optype == OpType.R_ANAL_OP_TYPE_CALL:
            is_call = True
            has_target = True
            target = int(anal_op.jump)
            if addr in false_call:
                # print "call", hex(addr), "in false_call"
                if useTrace:
                    disas_seq = False
                else:
                    desc = desc + " (obf)"
            else:
                disas_seq = True
        elif optype == OpType.R_ANAL_OP_TYPE_UJMP or optype == OpType.R_ANAL_OP_TYPE_RET:
            disas_seq = False
        elif optype == OpType.R_ANAL_OP_TYPE_REP:
            has_target = True
            target = addr

        if "int" in desc:
            # print hex(addr), ": ", desc, "->", "is int."
            is_int = True

        if desc is None and optype == OpType.R_ANAL_OP_TYPE_ILL:
            desc = "(illegal)"

        if desc == "None" or desc == "(illegal)":
            is_none = True
            disas_seq = False
            size = 1

        i = Instruction(addr, size, desc, is_call, has_target, target, is_jcc, disas_seq, is_none, is_int)
    else:
        print "Error in disas_at_r2 - not in range: ", hi(addr)
        # raise "Error in r2: not in range"
        i = None

    addr_info[addr]['inst'] = i
    return i


def disas_at(addr, virtual_offset, beginning, end, f):
    return disas_at_r2(addr, beginning, end)

class Layer:
    def __init__(self):
        self.insts = []
        self.debut = 0
        self.fin = 0

    def __init__(self, insts, debut, fin):
        self.insts = insts
        self.debut = debut
        self.fin = fin

    def __init__(self, addr, inst_to_l):
        self.insts = []
        self.debut = addr
        a = addr
        i = disas_at(a, virtual_offset, beginning, end, f)
        lasta_p_size = a + i.size - 1
        while beginning <= a and a + i.size <= end + 1:
            if a in inst_to_l:
                # print "already!!"
                self.insts.append(str("@")+str(inst_to_l[a]))
                break
            else:
                self.insts.append(a)
            if i.size == 0:
                raise "Size is 0."
            a += i.size
            lasta_p_size = a - 1
            if beginning <= a <= end:
                i = disas_at(a, virtual_offset, beginning, end, f)
            else:
                break
        self.fin = lasta_p_size

    def __str__(self):
        if self.insts:
            str_insts = "["
            for i in self.insts:
                str_insts += hi(i) + " "
            str_insts += "]"
        else:
            str_insts = ""
        s = "Layer: (debut, fin)=(%s, %s), insts: %s" % (hi(self.debut), hi(self.fin), str_insts)
        return s

    def to_str(self, i, detailled=False):
        if self.insts:
            str_insts = "["
            for k in self.insts:
                if type(k) is str:
                    str_insts += "@" + hi(int(k[1:]))
                else:
                    if detailled:
                        str_insts += str(disas_at(k, virtual_offset, beginning, end, f))
                    else:
                        str_insts += hi(k)
                str_insts += " "
            str_insts += "]"
        else:
            str_insts = ""
        s = "Layer @%s: (debut, fin)=(%s, %s), insts: %s" % (hi(i), hi(self.debut), hi(self.fin), str_insts)
        return s


def add_layer_to_inst_to_layer(layer, i_to_l):
    # layer = Layer(layer_addr)
    for i in layer.insts:
        if type(i) is not str:
            if i in i_to_l:
                print "hum ??"
            i_to_l[i] = layer.debut


def rm_layer_to_inst_to_layers(layer_addr, i_to_l):
    layer = Layer(layer_addr)
    for i in range(beginning, end + 1):
        if i in layer.insts and i in i_to_l:
                i_to_l[i].remove(layer.debut)


# def inst_to_layers(layers):
#     i_to_l = dict()
#     for i in range(beginning, end + 1):
#         s = set()
#         for j in range(len(layers)):
#             if i in layers[j].insts:
#                 s.add(j)
#         if s:
#             i_to_l[i] = s
#     return i_to_l


def get_first_block_having(g, inst):
    nodes = g.nodes()
    for b in nodes:
        if b.contains_inst(inst):
            return True, b
    return False, None


def split_block(b, addr, g):
    b2 = BasicBlock(addr)
    b2.insts_int = [x for x in b.insts_int if x >= addr]
    b2.size = int(b.addr - addr + b.size)
    g.add_node(b2)
    for e in g.out_edges(b, data=True):
        u, v, d = e
        connect_to(g, b2, v, d['color'])
        g.remove_edge(u, v)
    connect_to(g, b, b2)
    b.size = int(addr - b.addr)
    b.insts_int = [x for x in b.insts_int if x < addr]
    return b2


def split_all_blocks(g):
    c = 1
    while c != 0:
        c = 0
        for n in g.nodes():
            if len(n.insts_int) > 1:
                c += 1
                split_block(n, n.insts_int[1], g)
                # break


def is_node_simple_and_succ(g, n, addr_in_conflicts):
    simple = True

    outp = g.out_edges(n, data=True)
    inp = g.in_edges(n, data=True)
    edges = outp + inp
    for e in edges:
        u, v, d = e
        # if d['color'] != "red" or d['color'] != "black" or d['color'] != "pink":
        #     simple = False
        if 'aligned' in d and not d['aligned']:
            simple = False
    if n.addr in addr_in_conflicts:
        simple = False
    if len(outp) >= 1:
        succ = outp[0][1]
    else:
        succ = None

    return simple, succ, len(outp), len(inp)


def group_seq(g, addr_in_conflicts):
    nodes_to_remove = set()

    for n in g.nodes():
        if n not in nodes_to_remove:
            s, succ, n_out, n_in = is_node_simple_and_succ(g, n, addr_in_conflicts)
            if s and succ:
                s2, succ2, n_out2, n_in2 = is_node_simple_and_succ(g, succ, addr_in_conflicts)
                all_succ_from_n = True
                all_n_to_succ = True

                for e in g.out_edges(n):
                    u, v = e
                    if v.addr != succ.addr:
                        all_n_to_succ = False

                for e in g.in_edges(succ):
                    u, v = e
                    if u.addr != n.addr:
                        all_succ_from_n = False

                if s2 and all_succ_from_n and all_n_to_succ and n.addr + n.size == succ.addr \
                        and addr_info[n.addr]['color'] == addr_info[succ.addr]['color']\
                        and (('trace' not in addr_info[n.addr] and 'trace' not in addr_info[succ.addr])
                             or ('trace' in addr_info[n.addr] and 'trace' in addr_info[succ.addr]
                                 and addr_info[n.addr]['trace'] == addr_info[succ.addr]['trace'])):

                    # regroup n and succ:
                    for i in succ.insts:
                        # inst = disas_at(i, virtual_offset, beginning, end, f)
                        n.add_inst(i)
                    for e in g.out_edges(succ, data=True):
                        u, v, d = e
                        connect_to(g, n, v, d['color'], d['st_dyn'])
                    nodes_to_remove.add(succ)

    for n in nodes_to_remove:
        g.remove_node(n)

    return len(nodes_to_remove)


def group_all_seq(g, addr_in_conflicts):
    a = 1
    while a != 0:
        a = group_seq(g, addr_in_conflicts)


def connect_to(g, block, b, color="black", st_dyn="static"):
    # print "connecting", "["+hi(block.addr), hi(block.size+block.addr-1)+"]", "["+hi(b.addr), hi(b.size+b.addr-1)+"]"
    if st_dyn != "static":
        d_from = g.get_edge_data(block, b, default=None)
        if d_from is not None:
            for i in d_from:
                d = d_from[i]
                if d['st_dyn'] == "static":
                    d['st_dyn'] = "both"
        else:
            g.add_edge(block, b, color=color, st_dyn=st_dyn)
    else:
        g.add_edge(block, b, color=color, st_dyn="static")


def addr_to_block(g, addr):
    for n in g.nodes():
        if addr in n.insts_int:
            return n


def make_basic_block(beginning, end, virtual_offset, addr, g, f, fsize):
    block = BasicBlock(addr)

    while beginning <= addr <= end:
        inst = disas_at_r2(addr, beginning, end)
        (exist, b) = get_first_block_having(g, inst)

        if exist:
            if addr != b.addr:
                print "split"
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

            # finding successors to disassemble from them:
            if inst.addr == trace_last_addr:
                return block

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
                    if not inst.disas_seq:
                        return block
                    else:
                        addr += inst.size
    return block


def addr_in_graph(g, addr):
    for n in g.nodes():
        if n.addr == addr:
            return True, n
    return False, None


def addr_in_graph2(addr):
    if addr in addr_info and 'node' in addr_info[addr]:
        return True, addr_info[addr]['node']
    else:
        return False, None


def add_node_to_graph(block, g):
    if block.addr not in addr_info:
        addr_info[block.addr] = dict()

    addr_info[block.addr]['node'] = block
    g.add_node(block)


def make_basic_block2(beginning, end, virtual_offset, addr, g, f, fsize, m_gram):
    #nm1_grams list with n-n_n_gram, n-n_n_gram+1, ... n-1 inst type

    # print len(g.nodes())
    block = BasicBlock(addr)
    # exists, existing_block = addr_in_graph2(g, addr)
    exists, existing_block = addr_in_graph2(addr)
    inst = disas_at(addr, virtual_offset, beginning, end, f)

    if exists:
        block = existing_block
    else:
        block.add_inst(inst)
        # g.add_node(block)
        add_node_to_graph(block, g)

    b_inst = block.insts[0]
    m_gram = list(m_gram)
    t = tuple(m_gram)

    if addr not in addr_to_m_gram or t not in addr_to_m_gram[addr]:
        # first time arriving there with this m_gram before
        # print "first", hex(addr), t
        if addr not in addr_to_m_gram:
            addr_to_m_gram[addr] = set()
        addr_to_m_gram[addr].add(t)
        # print "len", len(nm1_grams)
        opcode = inst.desc.split()[0]
        if opcode == "stosb":
            opcode = "stosw"
        m_gram.append(opcode)
        # print hex(b_inst.addr), ":", m_gram
        if len(m_gram) == n_n_gram:
            # print "sized"
            n_gram = tuple(m_gram)
            # print "all 3", n_gram
            if n_gram in n_grams:
                p = n_grams[n_gram]
                # print "p known", p, hex(b_inst.addr)
            else:
                # print n_gram, "-> P=0.0"
                p = 0.0
            m_gram.pop(0)
        else:
            p = None

        # print hi(addr), "p:", p

        if b_inst.prob is None or p > b_inst.prob:
            # print "setting", p, hex(b_inst.addr)
            b_inst.prob = p
    else:
        if exists:
            return block

    if b_inst.is_none:
        block.head_is_none = True

    # finding successors to disassemble from them:
    if not useTrace or b_inst.addr != trace_last_addr:
        has_succ = False
        all_succ_goto_none = True

        if b_inst.has_target:
            has_succ = True
            target = b_inst.target
            if beginning <= target <= end:
                b = make_basic_block2(beginning, end, virtual_offset, target, g, f,
                                      fsize, m_gram)
                if not exists:
                    connect_to(g, block, b, "red")
                if not b.head_is_none:
                    all_succ_goto_none = False

        if b_inst.disas_seq:
            has_succ = True
            if beginning <= b_inst.addr + b_inst.size <= end:
                b = make_basic_block2(beginning, end, virtual_offset, b_inst.addr + b_inst.size, g, f,
                                      fsize, m_gram)
                if not exists:
                    connect_to(g, block, b)
                if not b.head_is_none:
                    all_succ_goto_none = False

        if has_succ and all_succ_goto_none and not b_inst.is_int \
                and not ((b_inst.is_jcc or b_inst.is_call) and not b_inst.has_target):
            block.head_is_none = True
        # if not has_succ and b_inst.desc != "None":
        #     print hex(b_inst.addr), b_inst.desc, "is final."
    return block

set_addr_in_layers = set()
def addr_in_layers3(addr, layers):
    return addr in set_addr_in_layers


addr_aligned_with_addr = dict()
def addr_aligned(addr1, addr2):
    min_a = min(addr1, addr2)
    max_a = max(addr1, addr2)
    if (min_a, max_a) in addr_aligned_with_addr:
        return addr_aligned_with_addr[(min_a, max_a)]
    else:
        l = Layer(min_a, set())
        # for a in l.insts:
        #     print "  ", hi(a)
        for n in l.insts:
            addr_aligned_with_addr[(min_a, n)] = True

        r = max_a in l.insts
        addr_aligned_with_addr[(min_a, max_a)] = r
        return r


def sweep_and_classify(addr, addr_aligned_with_addr2, addr2, classify):
    print "sweeping", hi(addr)
    insts = []
    a = addr
    i = disas_at(a, virtual_offset, beginning, end, f)
    while beginning <= a and a + i.size <= end + 1:
        insts.append(a)
        if classify:
            addr_aligned_with_addr2[(addr, a)] = True
            if i.size == 0:
                raise "Size is 0."
            for j in range(a + 1, a + i.size):
                for k in insts:
                    addr_aligned_with_addr2[(k, j)] = False
        a += i.size
        if not classify and a == addr2:
            return True
        if beginning <= a <= end:
            i = disas_at(a, virtual_offset, beginning, end, f)
        else:
            break
    return False


addr_aligned_with_addr2 = dict()
def addr_aligned2(addr1, addr2):
    min_a = min(addr1, addr2)
    max_a = max(addr1, addr2)
    if (min_a, max_a) in addr_aligned_with_addr2:
        return addr_aligned_with_addr2[(min_a, max_a)]
    else:
        if min_a == addr2:
            sweep_and_classify(min_a, addr_aligned_with_addr2, None, True)
        else:
            sweep_and_classify(min_a, addr_aligned_with_addr2, max_a, False)
            return addr_aligned_with_addr2[(min_a, max_a)]


def addr_aligned_with_layer(addr, layer):
    return addr_aligned2(addr, layer[0])


def get_first_aligned_layer(addr, layers):
    for i in range(len(layers)):
        if addr_aligned_with_layer(addr, layers[i]):
            return True, i
    return False, None


addr_layer_to_aligned_addr = dict()
def make_basic_block3(beginning, end, virtual_offset, addr, f, fsize, layers):
    exists = addr_in_layers3(addr, layers)
    inst = disas_at(addr, virtual_offset, beginning, end, f)

    if inst is not None and not exists and beginning <= addr <= addr + inst.size - 1 <= end:
        print "disas at", hi(beginning), hi(addr), hi(addr + inst.size - 1), hi(end)
        r, min_i = get_first_aligned_layer(addr, layers)
        if r:
            layer = layers[min_i]
            bisect.insort(layer, addr)
        else:
            layer = [addr]
            layers.append(layer)
        set_addr_in_layers.add(addr)

        if inst.disas_seq:
            layers = make_basic_block3(beginning, end, virtual_offset, inst.addr + inst.size, f, fsize, layers)
        if inst.has_target:
            target = inst.target
            layers = make_basic_block3(beginning, end, virtual_offset, target, f, fsize, layers)
    return layers


def conflict_in_subset(conflict, conflicts):
    for c in conflicts:
        if c != conflict and conflict.issubset(c):
            # print "subset of conflict detected!"
            return True
    return False


def compute_conflicts(g, beginning, end, mode): #mode: trace or hybrid
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
    for n in g.nodes():
        if mode == "hybrid" or (mode == "trace" and n.addr in addr_info
                                and 'trace' in addr_info[n.addr] and addr_info[n.addr]['trace']):
            for i in range(n.addr, n.addr + n.size):
                if not i in addr_to_conflict:
                    addr_to_conflict[i] = [n]
                else:
                    addr_to_conflict[i].append(n)

    for i in range(beginning, end + 1):
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

    return conflicts, addr_in_conflicts


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


def set_to_str(c):
    s = ""
    for n in c:
        s += str(hex(int(n.addr))) + " "
    return s


def set_to_hi_str(c):
    s = ""
    for n in c:
        s += hi(n) + " "
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
        inst = disas_at(n.insts_int[0], f, fsize)
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


def add_trace_edges(g, trace_list):
    edges_done = set()
    a_to_b = dict()

    for i in range(len(trace_list)-1):
        if beginning <= trace_list[i] <= end and beginning <= trace_list[i+1] <= end:
            u = trace_list[i]
            v = trace_list[i+1]

            if u in a_to_b:
                bu = a_to_b[u]
            else:
                has, block = get_first_block_having(g, disas_at(u, virtual_offset, beginning, end, f))
                if has:
                    bu = block
                else:
                    bu = BasicBlock(u)
                    g.add_node(bu)
                a_to_b[u] = bu

            if trace_list[i] not in addr_info:
                addr_info[trace_list[i]] = dict()

            if not useTrace and bu.insts[0].prob is not None and bu.insts[0].prob <= p_quantile:
                addr_info[trace_list[i]]['color'] = "purple"
            else:
                addr_info[trace_list[i]]['color'] = "pink"

            addr_info[trace_list[i]]['trace'] = True

            if v in a_to_b:
                bv = a_to_b[v]
            else:
                has, block = get_first_block_having(g, disas_at(v, virtual_offset, beginning, end, f))
                if has:
                    bv = block
                else:
                    bv = BasicBlock(v)
                    g.add_node(bv)
                a_to_b[v] = bv

            if frozenset([u, v]) not in edges_done:
                connect_to(g, bu, bv, "red", st_dyn="dyn")
                edges_done.add(frozenset([u, v]))

    addr_info[trace_list[0]]['color'] = "orange"
    addr_info[trace_list[0]]['trace'] = True
    if trace_list[-1] not in addr_info:
        addr_info[trace_list[-1]] = dict()
    addr_info[trace_list[-1]]['color'] = "lightblue"
    addr_info[trace_list[-1]]['trace'] = True


def color_nodes(g):
    nodes_to_remove = set()
    for n in g.nodes():
        if n.addr not in addr_info or 'color' not in addr_info[n.addr] \
                or addr_info[n.addr]['color'] not in ("pink", "purple", "orange", "lightblue"):
            addr_info[n.addr] = dict()
            if n.addr == entrypoint:
                addr_info[n.addr]['color'] = "orange"
            elif n.head_is_none:
                nodes_to_remove.add(n)
            else:
                addr_info[n.addr]['color'] = "white"

    for n in nodes_to_remove:
        g.remove_node(n)


def sweep_layer(a, inst_to_l, layers):
    if a not in inst_to_l:
        new_l = Layer(a, inst_to_l)
        layers[new_l.debut] = new_l
        add_layer_to_inst_to_layer(new_l, inst_to_l)


# returns True if the layer l realigns with layer where l2_debut is
def layer_realigns(layers, l, l2_debut, max_addr):
    tmp_l = l
    while True:
        if tmp_l.debut == l2_debut:
            return True
        if type(tmp_l.insts[-1]) is str:
            if tmp_l.fin < max_addr:
                tmp_debut = int(tmp_l.insts[-1][1:])
                tmp_l = layers[tmp_debut]
            else:
                return False
        else:
            break
    return False


def count_dis_jumps(g, inst_to_l, mode, mark_edges, layers):
    n = 0

    for e in g.edges(data=True):
        u, v, d = e
        if mode == "hybrid" or (mode == "trace" and (d['st_dyn'] == "dyn" or d['st_dyn'] == "both")):
            min_a = min(u.addr, v.addr)
            max_a = max(u.addr, v.addr)
            if min_a not in inst_to_l or max_a not in inst_to_l:
                print "disJumps: addr in no layer"
            else:
                l = inst_to_l[min_a]
                l2 = inst_to_l[max_a]
                if layer_realigns(layers, layers[l], l2, max_a):
                    if mark_edges:
                        d['aligned'] = True
                else:
                    if mark_edges:
                        d['aligned'] = False
                    n += 1
    return n


def layers_stats(g, mode, mark_edges=False): #mode: hybrid, trace
    layers = dict()
    inst_to_l = dict()
    list_addr_to_sweep = []
    for n in g.nodes():
        if mode == "hybrid" or (mode == "trace" and n.addr in addr_info
                                and 'trace' in addr_info[n.addr] and addr_info[n.addr]['trace']):
            list_addr_to_sweep.append(n.addr)

    list_addr_to_sweep.sort()
    for a in list_addr_to_sweep:
        sweep_layer(a, inst_to_l, layers)

    n_dis_jumps = count_dis_jumps(g, inst_to_l, mode, mark_edges, layers)
    return layers, n_dis_jumps


def disas_segment(beginning, end, virtual_offset, f):
    print "beginning:", hi(beginning), "; end:", hi(end)
    g = nx.MultiDiGraph()

    print "Disassembling file..."
    layers = []
    for a in range(beginning, end + 1):
        # print inst
        # if inst.has_target or inst.addr == beginning:
        # print hi(inst.addr), hi(virtual_offset)
        # if inst.addr == beginning: #or inst.addr == 0x4:

        if a in trace_dict or a == entrypoint:
            make_basic_block2(beginning, end, virtual_offset, a, g, f, fsize, [])
            layers = make_basic_block3(beginning, end, virtual_offset, a, f, fsize, layers)

    # print "exiting"
    # for i in range(len(layers)):
    #     print "layer", i
    #     s = ""
    #     layers[i].sort()
    #     for a in layers[i]:
    #         s += " " + hi(a)
    #     print s
    # exit(0)
    # print "Splitting blocks..."
    # split_all_blocks(g)

    # print "min", hi(min([n.insts[0].addr for n in g.nodes()]))
    # print "max", hi(max([n.insts[0].addr for n in g.nodes()]))
    # exit(0)

    if trace_list:
        print "Adding trace edges..."
        add_trace_edges(g, trace_list)
    print "Coloring blocks and removing None..."
    color_nodes(g)
    print len(g.nodes()), "nodes in initial graph."

    print "Sweeping layers..."
    layers_trace, n_dis_jumps_trace = layers_stats(g, "trace", False)
    layers_hybrid, n_dis_jumps_hybrid = layers_stats(g, "hybrid", True)
    print len(layers_trace), "active layers and", n_dis_jumps_trace, "disalignment jumps from trace."
    print len(layers_hybrid), "active layers and", n_dis_jumps_hybrid, "disalignment jumps from hybrid disassembly."

    # for e in g.edges(data=True):
    #     u, v, d = e
    #     print hi(u.addr), "->", hi(v.addr), d['st_dyn']

    # for l in layers_trace:
    #     print layers_trace[l].to_str(layers_trace[l].debut, inst_to_l, False)
    #
    # for l in layers_hybrid:
    #     print layers_hybrid[l].to_str(layers_hybrid[l].debut, False)

    # print "Computing conflicts..."
    # conflicts, addr_in_conflicts = compute_conflicts(g, beginning, end)
    print "Grouping sequential instructions..."
    group_all_seq(g, dict())

    print "Computing conflicts..."
    conflicts_trace, addr_in_conflicts_trace = compute_conflicts(g, beginning, end, "trace")
    conflicts, addr_in_conflicts = compute_conflicts(g, beginning, end, "hybrid")
    print len(conflicts_trace), "conflicts,", len(addr_in_conflicts_trace), "bytes in conflicts in trace."
    print len(conflicts), "conflicts,", len(addr_in_conflicts), "bytes in conflicts in hybrid disassembly."

    print "trace:", len(layers_trace), n_dis_jumps_trace, len(conflicts_trace), len(addr_in_conflicts_trace)
    print "hybrid:", len(layers_hybrid), n_dis_jumps_hybrid, len(conflicts), len(addr_in_conflicts)
    # print set_to_hi_str(addr_in_conflicts)
    # resolve_conflicts(g, conflicts, beginning)
    # print "addr in conflicts"
    print len(conflicts), "conflicts remain."
    # print_conflicts(conflicts)
    draw_conflicts(g, conflicts)
    return g


def disas_file(beginning, end, virtual_offset, f):
    return disas_segment(beginning, end, virtual_offset, f)

def print_graph_to_file(path, virtual_offset, g, ep_addr, last_addr):
    f = open(path, 'wb')
    # f = sys.stdout
    f.write("digraph G {\n")
    f.write("labeljust=r\n")
    for n in g.nodes():
        color = addr_info[n.addr]['color']
        if n.addr in trace_dict:
            o = trace_dict[n.addr]
            if len(o) >= 4:
                ordres = str(o[0:3])[:-1] + "...]"
            else:
                ordres = str(o[0:3])
            # color = "pink"
            shape = "box"
        else:
            ordres = ""
            shape = "box"

        f.write("\"" + hex(int(n.addr)) + "\"" + " [label=\"" + ordres + " " + str(n).replace("\\n", "\l")
                + "\", shape=" + shape + ", style=\"bold, filled\""
                + ", shape=" + shape + ", fillcolor=\"" + color + "\"]\n")

    for e in g.edges(data=True):
        u, v, d = e

        if 'aligned' in d:
            change_layer = not d['aligned']
        else:
            change_layer = False

        arrow_size = 1.0
        if change_layer:
            dir_type = "both"
            arrow_head = "empty"
            arrow_tail = "odot"
        else:
            dir_type = "forward"
            arrow_tail = "none"
            arrow_head = "normal"

        if d['st_dyn'] == "static":
            style = "dashed"
            penwidth = 2
        elif d['st_dyn'] == "dyn":
            style = "solid"
            penwidth = 0.8
        elif d['st_dyn'] == "both":
            style = "bold"
            penwidth = 3

        if d['color'] == "green":
            d['color'] = "black"
            dir_type = "both"
            arrow_tail = "dot"
            arrow_head = "dot"
            style = "dotted"
            arrow_size = 0.5
            penwidth = 1.0

        f.write("\"" + hex(int(u.addr)) + "\"" + " -> " + "\"" + hex(int(v.addr)) +
                "\" [style="+style+", dir=" + dir_type + ", arrowhead=" + arrow_head
                + ", arrowtail=" + arrow_tail + ", penwidth=" + str(penwidth)
                + ", arrowsize=" + str(arrow_size)
                + ", color=" + d['color'] + "]\n")
    f.write("}")

g = disas_file(beginning, end, virtual_offset, f)
print_graph_to_file("file.dot", virtual_offset, g, trace_first_addr, trace_last_addr)