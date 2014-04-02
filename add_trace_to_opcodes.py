#!/usr/bin/python2.7
# coding: utf-8

import sys

if len(sys.argv) > 2:
    trace_path = sys.argv[1]
    opcodes_path = sys.argv[2]
else:
    print "2 args: .trace file, and opcodes file"
    exit(0)

f_trace = open(trace_path, "rb")
lines = [line.strip() for line in f_trace]
f_trace.close()

f_opcodes = open(opcodes_path, "a")

f_opcodes.write("##\n")
for l in lines:
    if "_" in l:
        a = l.split()
        if len(a) >= 4:
            opcode = a[3].lower()
            if opcode == "jnz":
                opcode = "jne"
            elif opcode == "jz":
                opcode = "je"
            elif opcode == "pusha":
                opcode = "pushad"
            elif opcode == "popa":
                opcode = "popad"
            elif opcode == "repnz":
                opcode = "repne"
            elif opcode == "stosb":
                opcode = "stosw"
            elif opcode == "stosd":
                opcode = "stosw"
            f_opcodes.write(opcode+"\n")