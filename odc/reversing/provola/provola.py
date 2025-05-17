from libdebug import debugger
import string

def provolino(t, bp):
    pass
d = debugger("./provola")

flag = b"$"*37
max_count = 0
for i in range(37):
    for c in string.printable:
        new_flag = flag[:i] + c.encode() + flag[i+1:]
        r = d.run()

        bp = d.bp(0x1A0F, file="provola", callback = provolino)
        d.cont()

        r.recvuntil(b'password.')
        r.sendline(new_flag)

        d.wait()
        d.kill()

        if bp.hit_count > max_count:
            max_count = bp.hit_count
            flag = new_flag
            print(f"New flag: {flag}")
            break
