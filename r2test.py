from r2 import r_core
import sys

addr = 0
if len(sys.argv) > 1:
    addr = int(sys.argv[1], 16)

rc = r_core.RCore()
# rc.file_open("/usr/bin/id", 0, 0)
rc.file_open("/home/aurelien/workspace/disasm/ex.bin", 0, 0)
rc.bin_load("", 0)

# rc.anal_all()
# funcs = rc.anal.get_fcns()

anal_op = rc.op_anal(addr)
print rc.anal.op_to_string(anal_op)
print rc.anal.op_to_esil_string(anal_op)
print("---  addr: 0x%x    ---" % anal_op.addr)
print("   | type:        %d" % anal_op.type)
print("   | mnemonic:        %s" % anal_op.mnemonic)
print("   | nopcode:     %s" % anal_op.nopcode)
print("   | family:     %d" % anal_op.family)
print("   | selector:     %d" % anal_op.selector)
print("   | ptr:     0x%x" % anal_op.ptr)
print("   | val:     0x%x" % anal_op.val)
print("   | size:        %d" % anal_op.size)
print("   | jump:        0x%x" % anal_op.jump)
print("   | fail:        0x%x" % anal_op.fail)

print rc.op_str(addr)
hex = ""
print rc.anal.op_hexstr(addr, hex)
print hex

# print("0x%x %s %s" % (0, asm_op.buf_hex, asm_op.buf_asm))


# for f in funcs:
#     blocks = f.get_bbs()
#     print("+" + (72 * "-"))
#     print("| FUNCTION: %s @ 0x%x" % (f.name, f.addr))
#     print("| (%d blocks)" % (len (blocks)))
#     print("+" + (72 * "-"))
#
#     for b in blocks:
#         print("---[ Block @ 0x%x ]---" % (b.addr))
#         print("   | size:        %d" % (b.size))
#         print("   | jump:        0x%x" % (b.jump))
#         print("   | conditional: %d" % (b.conditional))
#         print("   | return:      %d" % (b.returnbb))
#
#         end_byte = b.addr + b.size
#         cur_byte = b.addr
#
#         while (cur_byte < end_byte):
#             #anal_op = rc.op_anal(cur_byte)
#             asm_op = rc.disassemble(cur_byte)
#
#             # if asm_op.inst_len == 0:
#             #     print("Bogus op")
#             #     break
#
#             #print("0x%x %s" % (anal_op.addr, anal_op.mnemonic))
#             print("0x%x %s %s" % (cur_byte, asm_op.buf_hex, asm_op.buf_asm))
#             cur_byte += asm_op.inst_len