# Open What Write

it's just like "open read write" in the training challenge, but this time no read syscall allowed. 
1. create the /challenge/flag, otherwise it will always segfault in the local 
2. create a chain of syscall: open, mmap, and write for output 
3. open the /challenge/flag file 
4. use mmap to map the file grep -E 'open|mmap|write|exit' /usr/include/x86_64-linux-gnu/asm/unistd_64.h -E 'open|mmap|write|exit' /usr/include/x86_64-linux-gnu/asm/unistd_64.hgrep -E 'open|mmap|write|exit' /usr/include/x86_64-linux-gnu/asm/unistd_64.h the memory. 
5. write for the output 
6. like in the class, write string /challenge/flag to the end of the shellcode
7. calculating the offset with defuse.ca, this shellcode contains 0x5b bytes. the next one should be /challenge/flag string and i put them into my shellcode
8. p.send so it fits exactly the size of my shellcode