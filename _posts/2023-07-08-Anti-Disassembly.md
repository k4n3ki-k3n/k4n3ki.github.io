---
title : Anti-Disassembly(Chapter 15)
author : k4n3ki
date : 2023-07-08 1:00:00 +05:30
categories: [Practical Malware Analysis]
tags: [Anti-Reversing, Assembly]
---

These Labs are from Chapter 15(<span style="color:red">Anti-Disassembly</span>) for practice from the book <span style="color:lightgreen">“Practical Malware Analysis”</span> written by <span style="color:lightgreen">Michael Sikorski</span> and <span style="color:lightgreen">Andrew Honig</span>.

Tools used:
- Detect-it-Easy
- IDA Pro

# <span style="color:red">Lab 15-01</span>

> Analyze the sample found in the file LAb15-01.exe. This is a command-line program that takes an argument and prints "Good Job!" if the argument matches a secret code.

We don't get any information after opening it Detect-it-Easy. As it only imports some common functions from <span style="color:lightgreen">MSVCRT.dll</span>. 

So, let's open it in IDA Pro. When we try see the string "<span style="color:lightgreen">Good Job!</span>", we don't see any cross-refernce to it.

<img src="/assets/img/lab15/1stringref.png">

In IDA, we are unable to decompile the main function. We some red marked hex numbers with call instruction. One line above these instructions, we can see jz instructions that are jumping into the middle of these call instructions. Above that we can see the the anti disassembly technique that uses "<span style="color:lightgreen">A jump instruction with a constant condition</span>", i.e.: "<span style="color:lightgreen">xor eax, eax</span>". So the jump will always be taken as the zero flag will be set always after the xor instruction.

<img src="/assets/img/lab15/1ida.png">

But the jump destination is not disassembled due to fake call instruction. To alter the disassembly to show the jump destination, <span style="color:red">press D</span> on the call instruction to convert it into data.

<img src="/assets/img/lab15/1D.png">

Then <span style="color:red">press C</span> on the 8B hex byte to convert it into code.

> 0x8B is the opcode for mov.

Follow the same procedure to modify the instructions. This same technique is used at 4 locations in this executable, i.e. 0x401010, 0x401023, 0x40104B, 0x401062.

<img src="/assets/img/lab15/1idaEdit.png">

Select all the instructions from the address 0x401000 to 0x401077 and <span style="color:red">press P</span> to turn this code into a function. After this step we can decompile the main function.

<img src="/assets/img/lab15/1main.png">

Where we can see that it first checks for an argument and then it check whether it is "pdq" or not. If it is, it will print "Good Job!" otherwise it prints "<span style="color:lightgreen">Son, I am Disappoint.</span>".

## <span style="color:red">Question and Answers</span>

> Question 1: What anti-disassembly technique is used in this binary?

Answer: Jump instruiton with constant condition is being used by this binary.

> Question 2: What rogue opcode is the disassembly tricked into disassembling?

Answer: 0xE8, opcode for 5-byte call instruction is used for fake call instruction that will never be used, as the jump is taken to the next byte to 0xE8.

> Question 3: How many times is this technique used?

Answer: This technique and rogue byte is used 4 times.

> Question 4: What command-line argument will cause the program to print "Good JOb!"?

Answer: "pdq" is the correct argument that cause the program to print "Good Job!".

# <span style="color:red">Lab15-02</span>

> Analyze the malware found in the file Lab15-02.exe. Correct all anti-disassembly countermeasures before analyzing the binary in order to answer the questions.

First let's open the executable in Detect-it-Easy. It contains some strings("Bamboo::", "internet unable", "not enough name"), though these don't give any hint about its working. It imports networking functions from <span style="color:lightgreen">WININET.dll</span>, and imports function from <span style="color:lightgreen">WS2_32.dll</span> using ordinal numbers. It also imports ShellExecuteA from <span style="color:lightgreen">SHELL32.dll</span> which can be used to execute an executable.

```python3
'imp_ordinal_39' : 'imp_WSAEnumNetworkEvents',
'imp_ordinal_74' : 'imp_WSARemoveServiceClass'
```

<img src="/assets/img/lab15/2imports.png">

For further analysis, open it in IDA Pro. While scrolling through the main function disassembly, we encounter the first technique used by the malware after which IDA Pro couldn't disassemble the hex data. 

<img src="/assets/img/lab15/2first.png">

At 0x0040115A, we can see "<span style="color:lightgreen">test esp, esp</span>" instruction and after which there is a jnz instruction. It is working as a fake condition as ESP is always non-zero. The target for the jnz instruction is loc_40115E+1 which lies between a 5-byte jmp instruction at 0x0040115E.

Convert the instruction at 0x0040115E into data by pressing D.

<img src="/assets/img/lab15/2firstD.png">

Then press C on 0x0040115F to convert it into code.

<img src="/assets/img/lab15/2firstC.png">

Scrolling down, we again encounter an countermeasure at 0x004011D2 which is xoring eax to eax. It can also be corrected using the same technique as above.

Again at 0x00401215, there is a jmp instruction whose target is the second byte of itself. 

<img src="/assets/img/lab15/2second.png">

It can be corrected by converting it into data, then press C on 0x00401216 to turn it into code.

> To force IDA Pro to produce a clean graph, you can turn 0xEB into a nop byte. Edit -> Patch program -> change byte... . After changing the byte press C to convert it into code.

<img src="/assets/img/lab15/2secondC.png">

Down in main function, we again encounter an countermeasure at 0x40126D which can be corrected same as above. But at 0x4012EC, we see that it tries to jz in between of the mov instruction at 0x4012E6. 

<img src="/assets/img/lab15/2third.png">

To correct it, convert the instructions into data and convert the instructions into code from 0x4012E8.

<img src="/assets/img/lab15/2thirdC.png">

After it, convert all the db bytes into nop instructions. This will allow us to create a proper function. After all this, now we can view the main function in graph mode or decompile it view pseudocode.

Now, let's analyze the main function. First it retrieves the host name for the computer and increases its ascii value by 1. for example: z to a, b to c, 2 to 3, etc.

<img src="/assets/img/lab15/2main.png">

Then it passes the modified name as first parameter to <span style="color:lightgreen">InternetOpenA</span>. Then it calls a function sub_401386, which just creates a string and duplicates it. 

<img src="/assets/img/lab15/2urlstring.png">

Then it calls <span style="color:lightgreen">InternetOpenUrlA</span> with the string returned by the function. Then it reads the file from the URL in the Buffer. It gets the pointer to the first occurence of "<span style="color:lightgreen">Bamboo::</span>" in the content read from the URL. If not present, it return 0. If present then it searches another occurence of "::". Then it replaces second occurence of "::" with NULL. Then it calls another function sub_40130F, which duplicates another string, i.e: "<span style="color:lightgreen">Account Summary.xls.exe</span>" and stores it into FileName. 

Then add 8 to the pointer pointing to the occurence of "Bamboo::". Then passes the pointer to the InternetOpenUrlA, so it must be some kind of URL. It reads the content ot lpBuffer and creates a file of name "Account Summary.xls.exe" and writes the content to it. Then it executes the file using <span style="color:lightgreen">ShellExecuteA</span> function.


## <span style="color:red">Question and Answer</span>

> Question 1: What URL is initially requested by the program?

Answer: http[:]//www[.]practicalmalwareanalysis[.]com/bamboo.html

> Question 2: How is the User-Agent generated?

Answer: User-Agent is generated by adding 1 to each character of the host name of the computer.

> Question 3: What does the program look for in the page it initially requests?

Answer: Bamboo::

> Question 4: What does the program do with the information it extracts from the page?

Answer: It extracts a URL from the page that was between "Bamboo::" and "::". Then it read from that page, writes it to a file and execute it.


# <span style="color:red">Lab15-03</span>

> Analyze the malware found in the file Lab15-03.exe. At first glance, this binary appears to be a legitimate tool, but it actually contains more functionality than advertised.

Open the malware in Detect-it-Easy. After looking the strings, it seems to be some kind of process-listing tool.

<img src="/assets/img/lab15/3strings.png">

Among the imports, there are two functions that are not related to processes, i.e. <span style="color:lightgreen">WinExec</span> and <span style="color:lightgreen">URLDownloadToFileA</span>.

For further analysis, load the file into IDA Pro. In main function, we see that it first builds an address 0x40148C via ORing 0x400000 and 0x148C and stores it in <span style="color:lightgreen">[ebp+4]</span> which stores the <span style="color:lightgreen">return address</span>.

<img src="/assets/img/lab15/3oraddress.png">

IDA Pro didn't identified 0x40148C as function and remained as just orphaned code.

<img src="/assets/img/lab15/3first.png">

Above we can see the first anti-disassembly technique at 0x401494 in form of <span style="color:lightgreen">fake conditional</span>. As it always take the jump whose target is the second byte of the instruction at 0x401496. Press D on it to convert it into data and then press C on 0x401497 to convert back to code. 

There are some bytes that IDA converted into DWORDs instead of assembly. To convert it into assembly, press C.

At 0x4014D7, it tries to jump on the second byte of its own instruction. Press D on 0x4014D7 and press C on 0x4014D8 to convert it into code.

Scrolling down, i saw calls to sub_401534 with an argument of character stream(unk_403010 and unk_403040). The data in these memory locations didn't appear to be ASCII text. At 0x401510, these same locations are passed to URLDownloadToFileA. 

<img src="/assets/img/lab15/3urldownload.png">

Going through the function sub_401534, it seems that it just XORs every byte with 0xFF. Writing a script in python to see the decoded data:

<img src="/assets/img/lab15/3xorpython.png">

We can see that it is passing a filename(<span style="color:lightgreen">spoolsrv.exe</span>) and url(<span style="color:lightgreen">http[:]//www[.]practicalmalwaranalysis[.]co/tt.html</span>) to the URLDownloadToFileA. 

At 0x401515, we can see another anti-disassembly countermeasure. It is false conditional in the form of a combiniation of <span style="color:lightgreen">jz and jnz together</span>, whose target is the second byte of the instruction at 0x401519. Press D on 0x401519 and press C on 0x40151A to convert it into code. Then it calls WinExec with unk_403040(spoolsrv.exe) as argument. So, it will launch the executable and will be terminated manually with ExitProcess.

## <span style="color:red">Question and Answers</span>

> Question 1: How is the malicious code initially called?

Answer: It overwrites the return address from the main function.

> Question 2: What does the malicious code do?

Answer: The malicious code downloads a file and executes it.

> Question 3: What URl does the malware use?

Answer: http[:]//www[.]practicalmalwaranalysis[.]co/tt.html

> Question 4: What filename does the malware use?

Answer: spoolsrv.exe
