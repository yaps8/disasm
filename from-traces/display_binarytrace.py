#!/usr/bin/python -u
# -*- coding: utf-8 -*-

import sys,os,struct
import optparse
import distorm3

""" file binary struct description
Definition in C++ 
#pragma pack(1)
typedef struct _MemOp {
	char size;        // size of instruction at this address
	char type;        // type of action
	ADDRINT addr or BYTE[size];     // address or datas
} MemOp;
#pragma pack(8)

Action type:
X: address of instruction     => struct {inst_size,'X',inst_addr}
R: address of a read memory   => struct {rdata_size,'R',address of read memory} 
W: address of a write memory  => struct {wdata_size,'W',address of written memory,data written from memory}
D: opcode of instruction      => struct {opcode_size,'W',opcode}
L: layer number               => struct {1,'L',layer number}
"""
def ReadPINTrace(fileHandle,options):

  print "Parsing pintool trace file..."

  Rop, Wop, Xop, Dop, Lop = map(ord, 'RWXDL')
  current_eip=0
  layer=0

  while True:
    try:
      # detect if this is a MemOp record or a dump
      size, actionType = struct.unpack('BB', fileHandle.read(2))

      if actionType in (Rop, Xop):
        # MemOp record
        addr, = struct.unpack('I', fileHandle.read(4))
                
      elif actionType == Dop:
        # instruction dump
        opcode = fileHandle.read(size)
        #
 
      elif actionType == Wop:
        writeaddr, = struct.unpack('I', fileHandle.read(4))

        # write value
        if size == 4:
          value = struct.unpack('I', fileHandle.read(4))
        elif size == 3:
          value = struct.unpack('BBB', fileHandle.read(3))
        elif size == 2:
          value = struct.unpack('BB', fileHandle.read(2))
        elif size == 1:
          value = struct.unpack('B', fileHandle.read(1))
                   
      elif actionType == Lop:
        # Wave record
        addr, = struct.unpack('I', fileHandle.read(4))
        layer +=1

      else:
        print
        print 'Warning, unknown MemOp type encountered:', actionType
        sys.exit(0)
        continue

    except:
     # assume EOF encountered
     break

    if actionType == Xop:
      print
      print "%02d_0x%08x " % (layer,addr),

    elif actionType == Dop:
      l = distorm3.Decode(current_eip, opcode, distorm3.Decode32Bits)
            
      for ib in l:
        print "(%02x) %-20s %-25s" % (ib[1],  ib[3],  ib[2]),
    elif actionType == Wop:
      print "%c0x%08x (%d) => 0x%x " % (actionType,writeaddr,size,value[0]),
    else:
      print "%c0x%08x (%d) " % (actionType,addr,size),


def main():
   usage = "usage: %prog trace file"
   parser = optparse.OptionParser(usage)
   (options, args) = parser.parse_args()

   if len(args)>1:
     print usage
     sys.exit(1)

   TracefileHandle = open(args[0], "rb")
   ReadPINTrace(TracefileHandle,options)

if __name__ == '__main__':
    main()


