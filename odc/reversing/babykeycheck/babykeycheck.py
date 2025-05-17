from pwn import *

magic0 = [
0x1B,                 
0x51, 
0x17,
0x2A, 
0x1E,
0x4E, 
0x3D, 
0x10,
0x17,
0x46, 
0x49, 
0x14,
0x3D ]

babuzz ="babuzz" 

result3 = b""

for i in range (13):
    result3 += xor(babuzz[i%6], magic0[i])
print(result3)

# step 2
v40 = -69
v8 = ""

magic1 = [
0xEB,
0x51,
0xB0,
0x13,
0x85,
0xB9,
0x1C,
0x87,
0xB8,
0x26,
0x8D,
0x07
]

for i in range(12):
    byte = int(magic1[i]) - v40
    v40 += byte 
    v8 += chr(byte%256) # ensure that the byte is in the range of 0-255

print(str(result3+v8.encode()))

    

