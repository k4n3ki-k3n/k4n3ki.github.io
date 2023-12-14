---
title : GDB Python(pico CTF)
author : k4n3ki
date : 2023-11-12 1:00:00 -500
categories: [Reverse Engineering]
tags: [gdb, angr, picoCTF, python]
---

## <span style="color:red">Content</span>
- [Tools used](#tools-used)
- [Easy as gdb](#easy-as-gdb)
    - [Description](#description)
    - [Solution](#solution)
- [OTP Implementation](#otp-implementation)
    - [Description](#description-1)
    - [Solution](#solution-1)



## <span style="color:red">Tools Used</span>
- python
- gdb-pwndbg
- angr
- IDA Pro


## <span style="color:red">Easy as gdb</span>

### <span style="color:red">Description</span>

<span style="color:lightgreen">Points:</span> 160 points

<span style="color:lightgreen">Tags:</span> picoCTF 2021, Reverse Engineering

<span style="color:lightgreen">AUTHOR:</span> MCKADE

<span style="color:lightgreen">Description:</span> 

The flag has got to be checked somewhere... File: [brute](/assets/img/gdb_picoCTF/brute)

<span style="color:lightgreen">Hint 1:</span> https://sourceware.org/gdb/onlinedocs/gdb/Basic-Python.html#Basic-Python

<span style="color:lightgreen">Hint 2:</span> With GDB Python, I can guess wrong flags faster than ever before!

### <span style="color:red">Solution</span>

```
$ file brute
brute: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV) dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=7ef7ebc27d61a92e4c699bb95aae99d75a90b87f, stripped
```

The "file" command indicates that the given file is a 32-bit ELF binary. Load this binary into IDA Pro to display the assembly code and pseudo-code.

<img src="/assets/img/gdb_picoCTF/main.jpg">

Within the function sub_9AF, input is acquired through the fgets function, and the output "<span style="color:lightgreen">Correct!</span>" or "<span style="color:lightgreen">Incorrect.</span>" is printed based on the return value of the sub_8C4 function.

The function sub_8C4 serves as a checker, comparing the characters of the flag one by one with the characters of the hardcoded encrypted string within the binary.

<img src="/assets/img/gdb_picoCTF/cmp.jpg">

The problem can be solved using both GDB Python and Angr. Here are the scripts for each approach.

<span style="color:lightgreen">GDB script:</span>

Command to run the script : 
> gdb-pwndbg -n -q -ex "set pagination off" -ex "source sol.py" ./brute

```python
import string
import gdb

gdb.execute("b *0x5655598E")

flag = ""
ALPHABET = string.ascii_letters + string.digits + "{}_"


def read_reg(reg):
    return gdb.parse_and_eval("${}".format(reg))

def write_to_file(input):
    with open('input', 'w') as f:
        f.write(input)

    gdb.execute('run < input')

def check_letter(curr, index):
    for i in range(index):
        gdb.execute("continue")

    al = read_reg('eax')
    dl = read_reg('edx')
    if(al == dl):
        return True
    return False

for i in range(30):
    for letter in ALPHABET:
        print("[!] flag : " + flag)
        curr_otp = flag + letter
        curr_otp += "0"*(30-len(curr_otp))

        print("[!] Trying " + curr_otp)
        
        write_to_file(curr_otp)
        
        if check_letter(curr_otp, len(flag)):
            flag += letter

print(flag)
```
<img src="/assets/img/gdb_picoCTF/flag.jpg">

<span style="color:lightgreen">angr script:</span>

> [!] It took a considerable amount of time to compute the flag.

```python
import angr
import logging

logging.getLogger('angr').setLevel(logging.INFO)

p = angr.Project("brute")

state = p.factory.entry_state()
simgr = p.factory.simgr(state)

x = p.loader.main_object.min_addr

target = x + 0xA6B
avoid = x + 0xA7F

simgr.explore(find = target, avoid = avoid)

if(simgr.found):
    print(simgr.found[0].posix.dumps(0))
else:
    print("[!] Couldn't find the solution :)")
```

<img src="/assets/img/gdb_picoCTF/angr.jpg">

> Flag : picoCTF{I_5D3_A11DA7_61b3a698}

## <span style="color:red">OTP Implementation</span>

### <span style="color:red">Description</span>


<span style="color:lightgreen">Points:</span> 300 points

<span style="color:lightgreen">Tags:</span> picoCTF 2020 Mini-Competition, Reverse Engineering

<span style="color:lightgreen">AUTHOR:</span> MADSTACKS

Yay reversing! Relevant files: [otp](/assets/img/gdb_picoCTF/otp) [flag.txt](/assets/img/gdb_picoCTF/flag.txt)

<span style="color:lightgreen">Hint1:</span> https://sourceware.org/gdb/onlinedocs/gdb/Python-API.html

<span style="color:lightgreen">Hint2:</span> I think GDB Python is very useful, you can solve this problem without it, but can you solve future problems (hint hint)?

<span style="color:lightgreen">Hint3:</span> Also test your skills by solving this with ANGR!

### <span style="color:red">Solution</span>

```
$ file otp                                                              
otp: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=674d3f4dd902095f3b632572f0c244ca70573f3d, not stripped
```

The "file" command indicates that it is a 64-bit ELF binary. Upon execution, it prints "<span style="color:lightgreen">USAGE: ./otp [KEY]</span>" and when provided with a string argument, it outputs "<span style="color:lightgreen">Invalid key!</span>".

To analyze its functions, load it into IDA Pro. In the main function, there is a for loop that iterates through each character. Within this loop, each character is passed to a function named "<span style="color:lightgreen">valid_char</span>" which checks whether the character is in the set "<span style="color:lightgreen">abcdef0123456789</span>" or not.

<img src="/assets/img/gdb_picoCTF/validchar.jpg">

Next, it calls a function named "jumble" along with some operations that modify the input. Finally, it invokes strncmp to compare the altered input with a hardcoded string.

<img src="/assets/img/gdb_picoCTF/strcmp.jpg">

To solve this, we can use GDB Python by setting a breakpoint at the strncmp function and brute-force the solution by attempting all possible characters, index by index.

<span style="color:lightgreen">GDB script:</span>
```python
import string

gdb.execute("set disable-randomization on")
gdb.execute("b *0x5555554009bd")

flag = ""
ALPHABET = "abcdef" + string.digits


target = "occdpnkibjefihcgjanhofnhkdfnabmofnopaghhgnjhbkalgpnpdjonblalfciifiimkaoenpealibelmkdpbdlcldicplephbo"

for j in range(100):
    for i in ALPHABET:
        curr = "run " + flag + i
        curr += "0" * (100 - len(curr) + 4) 
        gdb.execute(curr)
        print("char : " + i + " index : " + str(j))
        x = gdb.selected_frame().read_register('rdi').cast(gdb.lookup_type('char').pointer()).string()
        print("result : ", x)
        if(target[j] == x[j]):
            flag += i
            break

print("flag : " , flag)
```

<img src="/assets/img/gdb_picoCTF/otp.jpg">

Upon passing these hexadecimal numbers to the binary, it outputs "You got the key, congrats! Now XOR it with the flag!". Therefore, just need to XOR it with the contents of the flag.txt file.

<img src="/assets/img/gdb_picoCTF/flag2.jpg">

<span style="color:lightgreen">angr script:</span>

```python
Coming Soon!
```

> Flag : picoCTF{cust0m_jumbl3s_4r3nt_4_g0Od_1d3A_15e89ca4}
