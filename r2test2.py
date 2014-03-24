from r2 import r_core
import sys

# rc.assembler.set_arch("x86")
# rc.assembler.set_bits(32)
# print rc.cmd_str("ao")
# virtual_offset = 0x01000000
virtual_offset = 0
offset = 0x00006e5b

rc = r_core.RCore()
# rc.file_open("telock99-hostname.bin.exe.snapshot2", 0, int(virtual_offset))
rc.file_open("running-ex", 0, int(virtual_offset))
# rc.file_open(sys.argv[1], 0, int(virtual_offset))
rc.bin_load("", 0)
# rc.cmd_str("o .//telock99-hostname.bin.exe.snapshot2 0x01000000")
rc.config.set_i('asm.arch', 32)
rc.assembler.set_bits(32)
rc.anal.set_bits(32)

# print hex(rc.offset)
# rc.offset = int(virtual_offset)
# print hex(rc.offset)

print("At 0x0:")
addrr = 0x0
anal_op = rc.op_anal(addrr)
addr = int(anal_op.addr)
size = abs(int(anal_op.size))
desc = str(rc.op_str(addrr))
optype = anal_op.type & 0xff
print hex(addrr), hex(addr), size, desc

print rc.cmd_str("s 0x0")
print rc.cmd_str("pd 2")

print("At 0x08048060:")
addrr = 0x08048060
anal_op = rc.op_anal(addrr)
addr = int(anal_op.addr)
size = abs(int(anal_op.size))
desc = str(rc.op_str(addrr))
optype = anal_op.type & 0xff
print hex(addrr), hex(addr), size, desc

print rc.cmd_str("s 0x08048060")
print rc.cmd_str("pd 2")

print("At 0x01006e5b:")
addrr = virtual_offset + offset
anal_op = rc.op_anal(addrr)
addr = int(anal_op.addr)
size = abs(int(anal_op.size))
desc = str(rc.op_str(addrr))
optype = anal_op.type & 0xff
print hex(addrr), hex(addr), size, desc

print rc.cmd_str("s 0x01006e5b")
print rc.cmd_str("pd 2")


print("At 0x00006e5b:")
addrr = offset
anal_op = rc.op_anal(addrr)
addr = int(anal_op.addr)
size = abs(int(anal_op.size))
desc = str(rc.op_str(addrr))
optype = anal_op.type & 0xff
print hex(addrr), hex(addr), size, desc

print rc.cmd_str("s 0x00006e5b")
print rc.cmd_str("pd 2")



# print rc.cmd_str("pd")

