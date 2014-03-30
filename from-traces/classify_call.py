#!/usr/bin/python2.7
# coding: utf-8
import sys

if len(sys.argv) > 1:
    path = sys.argv[1]
else:
    path = "trace3-addr-size02"

if len(sys.argv) > 2 and sys.argv[2] == "-v":
    verbose = True
else:
    verbose = False


calls = dict() # addr -> +1 addr
return_addr = set()


f = open(path, "rb")
lines = [line.strip() for line in f]
f.close()

true_call = set()
false_call = set()

n = 0
for i in range(len(lines)):
    l = lines[i]
    if "_" in l:
        a = l.split()
        # print l
        if len(a) >= 4:
            # print "0:", a[0], "1:", a[1], "2:", a[2], "3:", a[3]
            size = int(a[1][1:3], 16)
            if a[3] == "CALL":
                wave, addr = a[0].split("_")
                addr = int(addr, 16)
                if addr not in calls.keys():
                    n += 1
                ret_addr = addr + size
                calls[addr] = ret_addr

                if i + 1 < len(lines):
                    next_line = lines[i+1]
                    a = next_line.split()
                    next_wave, next_addr = a[0].split("_")
                    next_addr = int(next_addr, 16)
                    # print "added", hex(next_addr)
                    return_addr.add(next_addr)

            elif a[3] == "RET":
                wave, addr = a[0].split("_")
                addr = int(addr, 16)

                if i + 1 < len(lines):
                    next_line = lines[i+1]
                    a = next_line.split()
                    next_wave, next_addr = a[0].split("_")
                    next_addr = int(next_addr, 16)
                    return_addr.add(next_addr)

for a in calls.keys():
    if calls[a] in return_addr:
        if verbose:
            print "Legitimate:", hex(a)
        true_call.add(a)
    else:
        if verbose:
            print "Obfuscated:", hex(a)
        false_call.add(a)

total = len(calls)
print total, "calls:", len(true_call), "legitimate,", len(false_call), "obfuscated."
