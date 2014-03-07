from r2 import r_core

rc=r_core.RCore()
rc.file_open("test2.bin", 0, 0)
rc.bin_load("", 0)
# rc.assembler.set_arch("x86")
# rc.assembler.set_bits(32)
# rc.anal.set_bits(32)
# sc=r_core.Rsyscall()
# sc.setup("x86", 32, False, "linux")
rc.config.set_i('asm.bits', 32)
# rc.cmd0("e asm.bits = 32")
# rc.bits = "32"
print rc.cmd_str("ao")