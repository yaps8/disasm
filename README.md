# Introduction
This project is a disassembler using an execution trace and recursive disassembly to get accurate results. Besides it detects and counts code overlapping both in the trace and in the hybrid disassembly.

#Dependencies
It is needed to install Radare2 (http://www.radare.org/) and the python bindings.

One way is to do:

git clone git://github.com/radare/radare2 

and to follow the build instructions for radare2 and the bindings given here:
https://github.com/radare/radare2#introduction

If you run into troubles for compiling the python bindings, follow the more specific instructions given here:
https://github.com/radare/radare2-bindings/#description 
, especially consider installing the latest vala (there is a tarball) and valabind (from source)

# Use
The disassembler runs on python2.7 and examples can be found in the EXAMPLES file.
