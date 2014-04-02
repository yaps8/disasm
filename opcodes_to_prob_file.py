#!/usr/bin/python2.7
# coding: utf-8

import sys

if len(sys.argv) > 3:
    n_n_grams = int(sys.argv[1])
    opcodes_path = sys.argv[2]
    prob_path = sys.argv[3]
else:
    print "3 args: n (for n_grams), opcodes file, and opcodes.prob file"
    exit(0)

f_prob = open(prob_path, "wb")

opcodes = dict()
total = 0
m_gram = []
for line in open(opcodes_path):
    if "##" in line:
        m_gram = []
    else:
        total += 1
        opc = line[0:-1]
        m_gram.append(opc)
        if len(m_gram) == n_n_grams:
            t = tuple(m_gram)
            if t in opcodes:
                opcodes[t] += 1
            else:
                opcodes[t] = 1
            m_gram.pop(0)


def t_to_str(t):
    s = ""
    for i in range(len(t)):
        if i != 0:
            s += " "
        n = t[i]
        s += n
    return s

f_prob.write(str(n_n_grams) + "\n")
for op in opcodes.keys():
    ratio = 100 * (float(opcodes[op]) / float(total))
    f_prob.write(t_to_str(op) + " " + str(opcodes[op]) + " " + str(ratio)[0:7] + "\n")
    #print t_to_str(op), opcodes[op], str(ratio)[0:7]