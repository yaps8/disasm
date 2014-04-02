
opcodes = dict()
total = 0
for line in open('opcodes'):
    if not "#" in line:
        total += 1
        opc = line.lower()[0:-1]
        if opcodes.has_key(opc):
            opcodes[opc] += 1
        else:
            opcodes[opc] = 1

for op in opcodes.keys():
    ratio = 100 * (float(opcodes[op]) / float(total))
    print op, opcodes[op], str(ratio)[0:7]