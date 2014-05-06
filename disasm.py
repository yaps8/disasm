#!/usr/bin/python2.7
# coding: utf-8

import sys
import os
import networkx as nx
# from networkx import dag
from optparse import OptionParser
from r2 import r_core
import pefile
import sys
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
    Directed edges:
        Color:
            Red -> Jump target
            Black -> Next instruction
        Shape:
            Dashed -> From static analysis only
            Solid -> From trace only
            Bold -> Both
    Non-directed edges:
        Overlapping insructions:
            Black dotted edges
'''


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

                s += str(hex(int(inst.addr))) + " " + inst.desc + s_count + "\\n"
        return s

    def insts_to_hex(self):
        return [hex(int(i)) for i in self.insts_int]

    def __str__(self):
        s = "BB [" + str(hex(int(self.addr))) + " -> " + str(hex(int(self.addr+self.size-1))) \
                   + "](" + str(hex(int(self.size))) + ")\\n"
        s += self.insts_to_str()

        return s


def trace_from_path(lines, w):
    i = 0
    trace_dict = dict()
    trace_list = []
    for line in lines:
        i += 1
        if "#" not in line:
            if "_" in line:
                a = line.split()
                if len(a) >= 4:
                    wave, addr = a[0].split("_")
                    wave = int(wave)
                    addr = int(addr, 16)
                    if wave == w and beginning <= addr <= end:
                        trace_list.append(addr)
                        if addr in trace_dict:
                            trace_dict[addr].append(i)
                        else:
                            trace_dict[addr] = [i]
    if len(trace_list) == 0:
        return None, None, trace_list, trace_dict
    elif len(trace_list) == 1:
        return trace_list[0], trace_list[0], trace_list, trace_dict
    else:
        return trace_list[0], trace_list[-1], trace_list, trace_dict


def trace_from_simple_path(lines):
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


def get_wave(w, path):
    if w is not None:
        return w
    else:
        s = path.split("snapshot")
        if len(s) < 2:
            return None
        else:
            n = s[1]
            if n.isdigit():
                return int(n)
            else:
                return None


usage = "usage: %prog [options] binary_file" + "\n" + "       See the EXAMPLES file for usage examples," \
                                                      " use -h or --help to see all options."
parser = OptionParser(usage=usage)
parser.add_option("-T", "--trace",
                  type="string", dest="trace_detailled_path", default=None,
                  help="path of the detailled trace file (preferred)")
parser.add_option("-t", "--trace-simple",
                  type="string", dest="trace_list_path", default=None,
                  help="path of a simple trace file with only addresses (if no detailled trace is available)")
parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="more verbose output")
parser.add_option("-e", "--entrypoint",
                  type="string", dest="entrypoint", default=None,
                  help="entrypoint of the binary (hex)")
parser.add_option("-b", "--beginning",
                  type="string", dest="beginning", default=None,
                  help="first address of the binary (hex)")
parser.add_option("-l", "--end",
                  type="string", dest="end", default=None,
                  help="last address of the binary (hex)")
parser.add_option("-o", "--offset",
                  type="string", dest="offset", default=None,
                  help="offset of the binary (hex)")
parser.add_option("-w", "--wave",
                  type="int", dest="wave", default=None,
                  help="number of the wave to consider in trace, not necessary if "
                       "the input file path is *.snapshot[WAVE]")
parser.add_option("-s", "--display-trace",
                  action="store_false", dest="usetrace", default=True,
                  help="displays more nodes: do not restrict from trace")
parser.add_option("-x", "--dump",
                  action="store_true", dest="dump", default=False,
                  help="set if input is a memory dump and not a compiled binary file")
parser.add_option("-u", "--elf",
                  action="store_true", dest="elf", default=False,
                  help="set if input is an elf binary [default assumes PE]")

(options, args) = parser.parse_args()
if not args:
    parser.error("Needs at least an argument: binary file")

path = args[0]
useTrace = options.usetrace
verbose = options.verbose

pe_entrypoint = None
pe_virtual_offset = None

if not options.elf:
    pe = pefile.PE(path)
    pe_entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    pe_virtual_offset = pe.OPTIONAL_HEADER.ImageBase

f = open(path, "rb")
fsize = os.path.getsize(path)

if options.offset is not None:
    virtual_offset = int(options.offset, 16)
elif pe_virtual_offset is not None:
    virtual_offset = pe_virtual_offset
else:
    virtual_offset = 0

if options.beginning is not None:
    beginning = int(options.beginning, 16)
else:
    beginning = virtual_offset

if options.end is not None:
    end = int(options.end, 16)
else:
    end = beginning + fsize - 1

if options.entrypoint is not None:
    ep_known = True
    entrypoint = int(options.entrypoint, 16)
elif pe_entrypoint is not None:
    ep_known = True
    entrypoint = pe_entrypoint
else:
    ep_known = False
    entrypoint = beginning

true_call = set()
false_call = set()
opcodes_trace = []
trace_dict = dict()
trace_list = []
trace_first_addr = beginning
trace_last_addr = end
if options.trace_detailled_path is not None:
    wave = get_wave(options.wave, path)
    if wave is None:
        print "Wave could not be determined, please add the -w wave option."
        exit(0)
    elif verbose:
        print "Processing wave", wave
    fichier = open(options.trace_detailled_path, "rb")
    lines = [line.strip() for line in fichier]
    fichier.close()
    true_call, false_call, opcodes_trace = classify_calls(lines)
    trace_first_addr, trace_last_addr, trace_list, trace_dict = trace_from_path(lines, wave)
    if trace_first_addr is not None:
        entrypoint = trace_first_addr
elif options.trace_list_path is not None:
    fichier = open(options.trace_list_path, "rb")
    lines = [line.strip() for line in fichier]
    fichier.close()
    trace_first_addr, trace_last_addr, trace_list, trace_dict = trace_from_simple_path(lines)
    if trace_first_addr is not None:
        entrypoint = trace_first_addr

addr_info = dict()
rc = r_core.RCore()
bin = rc.file_open(path, 0, virtual_offset)

if options.dump:
    print "Loading binary dump (snapshot)."
else:
    print "Loading binary file (PE, ELF...)."
    rc.bin_load("", 0)

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

    def to_str(self, i, g, detailled=False):
        if self.insts:
            str_insts = "["
            for k in self.insts:
                if type(k) is str:
                    str_insts += "@" + hi(int(k[1:]))
                else:
                    if k in addr_info and 'node' in addr_info[k] and addr_info[k]['node'] in g:
                        if detailled:
                            str_insts += str(disas_at(k, virtual_offset, beginning, end, f))
                        else:
                            str_insts += hi(k)
                        str_insts += " "
            str_insts += "]"
        else:
            str_insts = ""
        s = "Layer @%s: %s" % (hi(i), str_insts)
        return s


def add_layer_to_inst_to_layer(layer, i_to_l):
    for i in layer.insts:
        if type(i) is not str:
            if i in i_to_l:
                print "i in i_to_l, that should not happen."
            i_to_l[i] = layer.debut


def get_first_block_having(g, inst):
    nodes = g.nodes()
    for b in nodes:
        if b.contains_inst(inst):
            return True, b
    return False, None


def is_node_simple_and_succ(g, n, addr_in_conflicts):
    simple = True

    outp = g.out_edges(n, data=True)
    inp = g.in_edges(n, data=True)
    edges = outp + inp
    for e in edges:
        u, v, d = e
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


def addr_in_graph(addr):
    if addr in addr_info and 'node' in addr_info[addr]:
        return True, addr_info[addr]['node']
    else:
        return False, None


def add_node_to_graph(block, g):
    if block.addr not in addr_info:
        addr_info[block.addr] = dict()

    addr_info[block.addr]['node'] = block
    g.add_node(block)


def make_basic_block2(beginning, end, virtual_offset, addr, g, f, fsize):
    block = BasicBlock(addr)
    exists, existing_block = addr_in_graph(addr)
    inst = disas_at(addr, virtual_offset, beginning, end, f)

    if exists:
        block = existing_block
    else:
        block.add_inst(inst)
        add_node_to_graph(block, g)

    b_inst = block.insts[0]
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
                                      fsize)
                if not exists:
                    connect_to(g, block, b, "red")
                if not b.head_is_none:
                    all_succ_goto_none = False

        if b_inst.disas_seq:
            has_succ = True
            if beginning <= b_inst.addr + b_inst.size <= end:
                b = make_basic_block2(beginning, end, virtual_offset, b_inst.addr + b_inst.size, g, f,
                                      fsize)
                if not exists:
                    connect_to(g, block, b)
                if not b.head_is_none:
                    all_succ_goto_none = False

        if has_succ and all_succ_goto_none and not b_inst.is_int \
                and not ((b_inst.is_jcc or b_inst.is_call) and not b_inst.has_target):
            block.head_is_none = True
    return block


def conflict_in_subset(conflict, conflicts):
    for c in conflicts:
        if c != conflict and conflict.issubset(c):
            return True
    return False


def compute_conflicts(g, beginning, end, mode): #mode: trace or hybrid
    conflicts = set()
    addr_in_conflicts = set()

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

    conflicts_in_subset = set()
    for c in conflicts:
        if conflict_in_subset(c, conflicts):
            conflicts_in_subset.add(c)

    for c in conflicts_in_subset:
        conflicts.remove(c)

    return conflicts, addr_in_conflicts


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
                print "disJumps: addr in no layer", hi(min_a), hi(max_a)
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
    g = nx.MultiDiGraph()

    print "Disassembling file..."
    print "beginning:", hi(beginning), "; end:", hi(end)
    for a in range(beginning, end + 1):
        if a in trace_dict or a == entrypoint:
            make_basic_block2(beginning, end, virtual_offset, a, g, f, fsize)

    if trace_list:
        print "Adding trace edges..."
        add_trace_edges(g, trace_list)
    print "Coloring blocks and removing invalid nodes..."
    color_nodes(g)
    print len(g.nodes()), "nodes in initial graph."

    print "Sweeping layers..."
    layers_trace, n_dis_jumps_trace = layers_stats(g, "trace", False)
    layers_hybrid, n_dis_jumps_hybrid = layers_stats(g, "hybrid", True)
    print len(layers_trace), "active layers and", n_dis_jumps_trace, "disalignment jumps from trace."
    print len(layers_hybrid), "active layers and", n_dis_jumps_hybrid, "disalignment jumps from hybrid disassembly."

    if verbose:
        for l in layers_hybrid:
            print layers_hybrid[l].to_str(layers_trace[l].debut, g, False)

    n_true_calls = 0
    n_false_calls = 0
    for n in g.nodes():
        if n.addr in true_call:
            n_true_calls += 1
        elif n.addr in false_call:
            n_false_calls += 1
    print "There are", n_true_calls + n_false_calls, "calls.", n_true_calls, "are legitimate and", n_false_calls, "are obfuscated."

    print "Grouping sequential instructions..."
    group_all_seq(g, dict())

    print "Computing overlapping instructions..."
    conflicts_trace, addr_in_conflicts_trace = compute_conflicts(g, beginning, end, "trace")
    conflicts, addr_in_conflicts = compute_conflicts(g, beginning, end, "hybrid")
    
    print len(conflicts_trace), "conflicts,", len(addr_in_conflicts_trace), "bytes in conflicts in trace."
    print len(conflicts), "conflicts,", len(addr_in_conflicts), "bytes in conflicts in hybrid disassembly."

    print "trace:", len(layers_trace), n_dis_jumps_trace, len(conflicts_trace), len(addr_in_conflicts_trace), \
          n_true_calls, n_false_calls, n_true_calls + n_false_calls
    print "hybrid:", len(layers_hybrid), n_dis_jumps_hybrid, len(conflicts), len(addr_in_conflicts)
    print len(conflicts), "conflicts remain."
    draw_conflicts(g, conflicts)
    return g


def disas_file(beginning, end, virtual_offset, f):
    return disas_segment(beginning, end, virtual_offset, f)


def print_graph_to_file(path, virtual_offset, g, ep_addr, last_addr):
    f = open(path, 'wb')
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
