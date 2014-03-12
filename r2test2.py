from r2 import r_core

rc=r_core.RCore()
rc.file_open("test3.bin", 0, 0)
rc.bin_load("", 0)
rc.config.set_i('asm.arch', 32)
# rc.assembler.set_arch("x86")
# rc.assembler.set_bits(32)
# print rc.cmd_str("ao")
virtual_offset = 0x08048060
offset = 0

addrr = virtual_offset + offset
anal_op = rc.op_anal(addrr)
addr = int(anal_op.addr)
size = abs(int(anal_op.size))
desc = str(rc.op_str(addrr))
optype = anal_op.type & 0xff

print hex(addrr), hex(addr), size, desc


# print rc.cmd_str("pd")