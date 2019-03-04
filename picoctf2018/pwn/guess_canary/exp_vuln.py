#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
debug = 1
arch_64 = 1
exe = "./vuln"

context.terminal = ["tmux","splitw","-h"]
e = ELF(exe)
if debug:
    context.log_level = "debug"

if len(sys.argv)>1:
    p = remote(sys.argv[1],int(sys.argv[2]))
    libc = ELF("./libc.so.6")
else:
    p = process([exe])
    if arch_64:
        libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
        arena = 0x3c4b20
        context.arch = "amd64"
    else:
        libc = ELF("/lib/i386-linux-gnu/libc.so.6")
        arena = 0x1b2780
        context.arch = "i386"

def sl(st):
    p.sendline(st)
def ru(st):
    return p.recvuntil(st)
def sd(st):
    p.send(st)
def z():
    gdb.attach(p)
def rl():
    p.recvline()

win = e.symbols["win"]

p.interactive()


