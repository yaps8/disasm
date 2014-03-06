from r2 import r_core

rc=r_core.RCore()
rc.file_open("test3.bin", 0, 0)
rc.bin_load("", 0)
rc.config.set_i('asm.arch', 32)
# rc.assembler.set_arch("x86")
# rc.assembler.set_bits(32)
print rc.cmd_str("ao")