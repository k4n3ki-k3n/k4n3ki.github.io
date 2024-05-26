---
title : Basic Binary Analysis in Linux
author : k4n3ki
date : 2024-05-27 1:00:00 +530
categories: [Binary Analysis]
tags: [Reversing, readelf, objdump, gdb]
---

[Practical Binary Analysis](https://practicalbinaryanalysis.com/) Book autholightgreen by Dennis Andriesse covers all major binary analysis topics in an accessible way, from binary formats, disassembly, and basic analysis to advanced techniques like binary instrumentation, taint analysis, and symbolic execution.

This blog covers the concepts and exercises from Chapter 5 of the book, focusing on basic binary analysis in Linux. The author uses a CTF challenge to illustrate the tools and techniques used in binary analysis.

## <span style = "color:red;">**Content**</span>
- [Challenge Description](#challenge-description)
- [Level 2](#level-2)
- [Level 3](#level-3)
- [Level 4](#level-4)
- [Level 5](#level-5)
- [Level 6](#level-6)

Level 1 is well explained in the chapter, so I will start from Level 2, which is unlocked using the flag from Level 1.

<img src="/assets/img/chapter5/levl1.png">

## <span style = "color:red;">Challenge</span>

Complete the new CTF challenge unlocked by the oracle program! You can complete the entire challenge using only the tools discussed in this chapter and what you learned in Chapter 2. After completing the challenge, don’t forget to give the flag you found to the oracle to unlock the next challenge.

<img src="/assets/img/chapter5/unlocklevel2.png">

## <span style = "color:red;">Level 2</span>

> Hint: Combine the parts

Checking the file type of a command using the <span style = "color:lightgreen;">*file*</span> utility.

```
$ file lvl2
lvl2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=457d7940f6a73d6505db1f022071ee7368b67ce9, stripped
```

The <span style = "color:lightgreen;">*nm*</span> utility, which lists symbols from object files, reveals that it employs functions such as rand and srand.

<img src="/assets/img/chapter5/2nm.png">

Running the program occasionally produces varying outputs, displaying random bytes each time. I utilized the sleep command to demonstrate the different outputs, as the seed for the srand function would be the same for all processes if executed simultaneously.

<img src="/assets/img/chapter5/2check.png">

Utilize <span style = "color:lightgreen;">*ltrace*</span> to trace the library function calls, revealing that it calls rand to generate a random number and put to print a byte.

<img src="/assets/img/chapter5/2ltrace.png">

Use <span style = "color:lightgreen;">*GDB*</span> to set a breakpoint at the puts call in order to analyze the surrounding instructions. 

<img src="/assets/img/chapter5/2gdb.png">

In GDB, a random number is generated using the rand function. This number is then utilized to index an array and retrieve a value, which appears to represent the flag. The flag needs to be passed to the oracle binary in order to unlock the next challenge.

<img src="/assets/img/chapter5/unlocklevel3.png">

## <span style = "color:red;">Level 3</span>

> Hint: Fix four broken things

Checking the file type of a command using the <span style = "color:lightgreen;">*file*</span> utility.

```
$ file lvl3
lvl3: ELF 64-bit LSB executable, Motorola Coldfire, version 1 (Novell Modesto), can't read elf program headers at 4022250974, for GNU/Linux 2.6.32, BuildID[sha1]=b6c0e8d914c6433e661b2cac794108671bdcaa06, stripped
```

The output contains several elements that appear inconsistent with an ELF 64-bit executable:
- <span style = "color:lightgreen;">*Motorola Coldfire*</span>: The Motorola Coldfire is a family of microprocessors developed by Motorola (now Freescale Semiconductor, a part of NXP). It is commonly used in embedded systems.
- <span style = "color:lightgreen;">*Version 1 (Novell Modesto)*</span>: This likely refers to the OS/ABI, which should be ELFOSABI_NONE (UNIX System V ABI) instead of ELFOSABI_MODESTO.
- "<span style = "color:lightgreen;">*Can't read ELF program headers at 4022250974*</span>": This is an error message indicating that the 'file' command encountelightgreen an issue while attempting to read the ELF program headers at a specific offset (4022250974). This could suggest corruption or an inconsistency in the file.

For viewing the ELF header, utilize the <span style = "color:lightgreen;">*readelf*</span> utility.

<img src="/assets/img/chapter5/3elfheader.png">

To rectify the discrepancies:
- Change the value of the <span style = "color:lightgreen;">*EI_OSABI*</span> field in the <span style = "color:lightgreen;">*e_ident*</span> array from <span style = "color:lightgreen;">*0xb(ELFOSABI_MODESTO)*</span> to <span style = "color:lightgreen;">*0x0(ELFOSABI_NONE)*</span>.
- Modify the <span style = "color:lightgreen;">*e_machine*</span> field in the ELF header from <span style = "color:lightgreen;">*0x34(EM_COLDFIRE)*</span> to <span style = "color:lightgreen;">*0x3e(EM_X86_64)*</span>.
- Adjust the value of <span style = "color:lightgreen;">*e_phoff*</span> in the ELF header from 0xdeadbeef to 0x40. This ensures that the program header comes after the ELF header, considering that the size of the ELF header is 64 bytes, as specified in the ELF header.

For making these changes, utilize a hex editor.

<img src="/assets/img/chapter5/3before.png">

After changes : 

<img src="/assets/img/chapter5/3after.png">

The file output now displays everything correctly, and the files execute successfully.

<img src="/assets/img/chapter5/3execute.png">

The flag was printed, but passing it to the oracle revealed that it's incorrect, indicating that there are still inconsistencies.

<img src="/assets/img/chapter5/3flagCheck.png">

CHecking the section headers showed that the section type of <span style = "color:lightgreen;">*.text*</span> section is set to <span style = "color:lightgreen;">*0x8(SHT_NOBITS)*</span> instead of <span style = "color:lightgreen;">*0x1(SHT_PROGBITS)*</span>.

<img src="/assets/img/chapter5/3sections.png">

The address of the <span style = "color:lightgreen;">*sh_type*</span> for the .text section can be calculated as the sum of the offset to the start of section headers and the size of section headers before the .text section.

> addr = e_shoff + e_shentsize * number of sections before .text

Please correct this and try the flag again.

<img src="/assets/img/chapter5/unlockLevel4.png">

## <span style = "color:red;">Level 4</span>

> Hint: Watch closely while I run

Checking the file type of a command using the <span style = "color:lightgreen;">*file*</span> utility.

```
$ file lvl4
lvl4: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f8785d89a1f11e7b413c08c6176ad1ed7b95ca08, stripped
```

It shows that lvl4 is a stripped 64-bit ELF executable for the x86-64 architecture, dynamically linked with shared libraries, intended to run on Linux kernel 2.6.32 or newer, and has a specific build identifier.

The strings utility shows that the file contains several strings, such as "FLAG" and "XaDht-+1432=/as4?0129mklqt!@cnz^", which seem like an encrypted flag.

<img src="/assets/img/chapter5/4strings.png">

The ltrace utility reveals that an environment variable named "FLAG" is set with the flag.

<img src="/assets/img/chapter5/4ltrace.png">

<img src="/assets/img/chapter5/unlockLevel5.png">

## <span style = "color:red;">Level 5</span>

Hints:
- Secrets hidden in code unused
- The method of redirection is the key
- Static rather than dynamically

Checking the file type of a command using the <span style = "color:lightgreen;">*file*</span> utility.

```
$ file lvl5
lvl5: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1c4f1d4d245a8e252b77c38c9c1ba936f70d8245, stripped
```

The strings utility reveals some interesting strings suggesting that this binary may include a decryption mechanism involving a key and a decrypted flag.

<img src="/assets/img/chapter5/5string.png">

Upon execution, it only displays the strings we saw in the output of the strings utility.

<img src="/assets/img/chapter5/5runcheck.png">

<span style = "color:lightgreen;">*readelf*</span> indicates that the entry point of the binary is at 0x400520.

<img src="/assets/img/chapter5/5elfheader.png">

<span style = "color:lightgreen;">*ltrace*</span> shows that 0x400500 is passed as the first argument to <span style = "color:lightgreen;">*__libc_start_main*</span>, indicating that the main function starts at 0x400500. Then, at 0x40050e, it calls the puts function to print the string "nothing to see here."

<img src="/assets/img/chapter5/5ltrace.png">

The disassembly in <span style = "color:lightgreen;">*objdump*</span> shows that the function at 0x400500 calls the puts function to print the string located at 0x400797.

<img src="/assets/img/chapter5/5mainhead.png">

Examining the <span style = "color:lightgreen;">*.rodata*</span> section with objdump reveals that the string "nothing to see here" is located at address 0x400797.

<img src="/assets/img/chapter5/5rodata.png">

The remaining code in the <span style = "color:lightgreen;">*.text*</span> section does not get executed. For example, the code starting at 0x400620 appears to load an encrypted string onto the stack, and the code at 0x4006a0 XORs it with the value at address 0x400540.

<img src="/assets/img/chapter5/5620.jpg">

We can try changing the argument passed to __libc_start_main from 0x400500 to 0x400620, ensuring that the loading and XORing instructions get executed.

<img src="/assets/img/chapter5/5gdbcheck.png">

The flag above is invalid. Upon closer inspection, both the actual address passed to __libc_start_main and the key printed are the same value, 0x400500. The key is retrieved from the instruction `40053d: 48 c7 c7 00 05 40 00 mov rdi,0x400500`. What if we edit these bytes to use the new function address (0x400620) instead?

<img src="/assets/img/chapter5/5byteedit.png">

After making this change, the binary now prints the flag upon execution.

<img src="/assets/img/chapter5/5flag.png">

<img src="/assets/img/chapter5/unlocklevel6.png">

## <span style = "color:red;">Level 6</span>

> Hint: Find out what I expect, then trace me for a hint

Checking the file type of a command using the <span style = "color:lightgreen;">*file*</span> utility.

```
$ file lvl6
lvl6: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=5702d22547fea17be6ca988688df47b9c6525e05, stripped
```

The <span style = "color:lightgreen;">*strings*</span> utility reveals a string indicating that this program might be expecting an argument.

<img src="/assets/img/chapter5/6string.png">

So, pass a dummy argument and use <span style = "color:lightgreen;">*ltrace*</span> to trace the library calls.

<img src="/assets/img/chapter5/6ltracecheck.png">

The ltrace output shows that the program compares the dummy input with "<span style = "color:lightgreen;">*get_data_addr*</span>" and prints prime numbers up to 100. Now, try using "get_data_addr" as the argument. This sets an environment variable named <span style = "color:lightgreen;">*DATA_ADDR*</span> with the value <span style = "color:lightgreen;">*0x4006c1*</span>.

<img src="/assets/img/chapter5/6ltrace.png">

If we examine the data instructions around that address, they appear to be gibberish.

```asm
4006c1: 2e 29 c6                cs sub esi,eax
4006c4: 4a 0f 03 a6 ee 2a 30    rex.WX lsl rsp,WORD PTR [rsi+0x7f302aee]
4006cb: 7f
4006cc: ec                      in     al,dx
4006cd: c8 c3 ff 42             enter  0xffc3,0x42
```

Combining these bytes reveals the flag.

<img src="/assets/img/chapter5/unlocklevel7.png">
