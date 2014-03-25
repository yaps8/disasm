#!/usr/bin/python

import pefile
import sys
pe =  pefile.PE(sys.argv[1])

if sys.argv[2] == "entrypoint":
    print hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
elif sys.argv[2] == "baseaddr":
    print hex(pe.OPTIONAL_HEADER.ImageBase)

