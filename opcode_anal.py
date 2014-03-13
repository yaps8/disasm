
opcodes = dict()
total = 0
for line in open('traces/opcodes'):
    total += 1
    opc = line.lower()[0:-1]
    if opcodes.has_key(opc):
        opcodes[opc] += 1
    else:
        opcodes[opc] = 1

for op in opcodes.keys():
    ratio = 1000 * (float(opcodes[op]) / float(total))
    print opcodes[op], "(", str(ratio)[0:5] ,"%%)" , op