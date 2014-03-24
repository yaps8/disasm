#!/usr/bin/python

import pefile
pe =  pefile.PE('/home/aurelien/trace-packers/telock99-hostname.bin/telock99-hostname.bin.exe')

print hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
print hex(pe.OPTIONAL_HEADER.ImageBase)

