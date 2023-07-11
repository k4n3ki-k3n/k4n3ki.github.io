---
title : Anti-Debugging(Chapter 16)
author : k4n3ki
date : 2023-07-11 01:00:00 -500
categories: [Practical Malware Analysis]
tags: [Anti-Debugging, Windows Internals]
---

These Labs are from Chapter 16(<span style="color:red">Anti-Debugging</span>) for practice from the book <span style="color:lightgreen">“Practical Malware Analysis”</span> written by <span style="color:lightgreen">Michael Sikorski</span> and <span style="color:lightgreen">Andrew Honig</span>.

Tools used:
- Detect-it-Easy
- PEview
- IDA Pro
- X32dbg
- OllyDbg

# <span style="color:red">Lab 16-01</span>

> Analyze the malware found in the Lab16-01.exe using a debugger. This is the same malware as Lab19-01.exe, with added anti-debugging techniques.

## <span style="color:red">Question and Answers</span>

> Question 1: Which anti-techniques does this malware employ?

Answer: After opening the malware in IDA Pro, we can clearly see that it is accessing <span style="color:lightgreen">BeingDebugged</span>, <span style="color:lightgreen">ProcessHeap</span> and <span style="color:lightgreen">NtGlobalFlag</span> to check, if it is running in a debugger or not.

<img src="/assets/img/lab16/1allthree.png">

We can see at 0x40355A, it checks for <span style="color:lightgreen">(fs:30h)+2</span> which contains the value of BeingDebugged flag.

Similarly, at in loc_403573 it checks for ProcessHeap at offset <span style="color:lightgreen">(0x30 + 0x18 + 0x10)</span> and at loc_403594 it checks for NtGlobalFlag at offset <span style="color:lightgreen">(0x30 + 0x68)</span>.

> Question 2: What happens when each anti-debugging technqiue succeeds?

Answer: If any technique succeeds then it calls a function sub_401000.

<img src="/assets/img/lab16/1deletefunc.png">

Where it frames a command("<span style="color:lightgreen">/c del C:\\Users\\vboxuser\\Desktop\\task\\Lab16-01.exe >> NUL</span>") to execute in cmd.exe by calling ShellExcuteA. This functions is used for <span style="color:lightgreen">self deletion</span>.

<img src="/assets/img/lab16/1delstring.png">

> Question 3: How can you get around these anti-debugging technqiues?

Answer: We can manualy set a breakpoint before the cmp instruction ad change the path of the jump. By chaning the zero flag or by changing the eax value.

<img src="/assets/img/lab16/1zeroflag.png">

But there are more than 70 occurences of the instruction "<span style="color:lightgreen">mov eax, large fs:30h</span>" which is used to get a pointer to the PEB structure.

So, instead of doing it manually, we can use x64Dbg plugin named <span style="color:lightgreen">ScyllaDbg</span> which has a lot of options in debugger hiding. It will automatically hide the debugger from the malware.

<img src="/assets/img/lab16/1scyllahide.png">

> Question 4: How do you manually change the structures checked during runtime?

Answer: When eax gets the pointer to the structure after the instructions like "mov eax, dword ptr ds:[eax+10]", you can follow the pointer into the dump and modify it.

> Question 5: Which OllyDbg plug-in will protect you from the anti-debugging technqiues used by this mawlare?

Answer: I used x64Dbg, for that you can use ScyllaHide.



# <span style="color:red">Lab 16-02</span>

Analyze the malware found in the Lab16-02.exe using a debugger. The goal of this lab is to figure out the correct password. The malware does not drop a malicious payload.

## <span style="color:red">Question and Answers</span>

> Question 1: What happens when you run Lab16-02.exe from the command line?

Answer: It exits after printing "<span style="color:lightgreen">usage: Lab16-02.exe <4 character password></span>".

<img src="/assets/img/lab16/2_1.png">

> Question 2: What happens when you run Lab16-02.exe and guess the command line parameter?

Answer: It exits after printing "<span style="color:lightgreen">Incorrect password, Try again.</span>".

<img src="/assets/img/lab16/2_2.png">

> Question 3: What is the command-line password?

Answer: <span style="color:lightgreen">bzrr</span> is the correct password.

<img src="/assets/img/lab16/2_3.png">

> Question 4: Load Lab16-02.exe into IDA Pro. Where in the main function is strncmp found?

Answer: <span style="color:lightgreen">strncmp</span> is at 0x40123A in main function.

> Question 5: What happens when you load this malware into OllyDbg using the default settings?

Answer: Process immediately terminates when loaded into OllyDbg.

> Question 6: What is unique about the PE structure of Lab16-02.exe?

Answer: Malware contains a <span style="color:lightgreen">.tls section</span>. We can see it in PEview.

<img src="/assets/img/lab16/2peview.png">

> Question 7: Where is the callback located? (Hint: Use CTRL-E in IDA Pro.)

Answer: We can see that <span style="color:lightgreen">TlsCallback_0</span> is at address 0x401060.

<img src="/assets/img/lab16/2ctrle.png">

> QUestion 8: Which anti-debugging technique is the program using to terminate immediately in the debugger and how can you avoid this check?

Answer: In TLS callback, it checks for a windows named "<span style="color:lightgreen">OLLYDBG</span>" using <span style="color:lightgreen">FindWindowA</span>. If it is present then it will exit. 

<img src="/assets/img/lab16/2windowcheck.png">

We can manually change the value of eax before jz instruction to avoid the exit call or it can also avoided by using the <span style="color:lightgreen">PhantOm</span> plugin.

> Question 9: What is the command-line password you see in the debugger after you disable the anti-debugging technique?

Answer: We can set a breakpoint at strncmp after disabling the plugins. bzqr is the password that we see.

<img src="/assets/img/lab16/2wpass.png">

> Question 10: Does the password found in the debugger work on the command line?

Answer: bzqr doesn't work on the commmand-line.

> Question 11: Which anti-debugging technique account for the different passwords in the debugger and on the command-line, and how can you protect against them?

Answer: TLS callback function calls a function sub_401020,in which the malware uses <span style="color:lightgreen">OutputDebugStringA</span> to check for the debugger. 

<img src="/assets/img/lab16/2outputstring.png">

In StartSddress function, it gets the value of <span style="color:lightgreen">BeingDebugged</span> flag.

<img src="/assets/img/lab16/2beingdebugged.png">

It uses the results of these techniques accordingly to decode the password.

# <span style="color:red">Lab 16-03</span>

> Analyze the malware in Lab16-03.exe using a debugger. This malware is similar to Lab09-02.exe, with certain modifications, including the introduction of anti-debugging techniques. If you get stuck, see Lab 9-2.

## <span style="color:red">Question and Answers</span>

> Question 1: Which strings do you see when using static analysis on the binary?

Answer: We can see the strings  by opening the malware into Detect-it-Easy. "<span style="color:lightgreen">cmd.exe</span>", "<span style="color:lightgreen">>> NUL</span>", "<span style="color:lightgreen">/c del</span>" are present in the malware which can be used for <span style="color:lightgreen">self-deletion</span>.

<img src="/assets/img/lab16/3strings.png">

> Question 2: What happens when you run this binary?

Answer:Nothing happens after running the the binary, it just terminates.

> Question 3: How must you rename the sample in order for it to run properly?

Answer: In main function it seems to be comparing two name using strncmp after a call to <span style="color:lightgreen">GetModuleFileNameA</span>. If the file name doesn't match then it returns from the main function.

<img src="/assets/img/lab16/3strncmp.png">

We can set a breakpoint at the call to strncmp and see the name of file it compares with.

At first we see that it compares the name of the malware(Lab16-03.exe) with "<span style="color:lightgreen">qgr.exe</span>". But even then the malware doesn't seem to be sending the request to domain.

<img src="/assets/img/lab16/3bstrncmp.png">

After disabling the anti-debugging techniques, we again check for the name at the call to strncmp, this tiime we can see that it compares the name with "<span style="color:lightgreen">peo.exe</span>".

<img src="/assets/img/lab16/3correctfilename.png">

If we change the malware name and try to run it, this time we can see that it tries to connect to a domain named "<span style="color:lightgreen">adg[.]malwareanalysisbook[.]com</span>".


> Question 4: Which anti-debugging techniques does this malware employ?

Answer:

### <span style="color:red">QueryPerformanceCounter</span>

In function sub_4011E0, it calls <span style="color:lightgreen">QueryPerformanceCounter</span> twice. If the difference between the results of these calls is greater than 1200 then it changes the value of a variable. Here a unhandled exception is caused by divide by zero instruction, on which the debugger automatically stops. This causes time delay.

<img src="/assets/img/lab16/3query.png">

### <span style="color:red">Check file residue</span>

At 0x401518, it calls strncmp where it comapres the name of the malware with a another string. The another string is modified by accordingly by the result of the above technique. If it fails then the malware exits.

### <span style="color:red">GetTickCount</span>

At loc_401584, the malware calls sub_401000 between two <span style="color:lightgreen">GetTickCount</span> calls.

<img src="/assets/img/lab16/3getickcount.png">

Function sub_401000, the malware causes an unhandled exception that the causes breakpoint at instruction "<span style="color:lightgreen">div ecx</span>". This breakpoint causes time delay that fails the check at 0x4015AD.

<img src="/assets/img/lab16/3seh.png">

### <span style="color:red">rdtsc</span>

At 0x4015CC, a function sub_401300 is called with three parameters("<span style="color:lightgreen">1qbz2wsx3edc</span>", buffer copied from unk_40604C, name variable). There are two rdtsc instructions in this function between them is the exception. After that the difference is compared to 0x7A120 at 0x401377. If this comparison fails then the malware deletes itself by calling the function sub_4010E0.

<img src="/assets/img/lab16/3rdtsc.png">

> Question 5: For each technique, what does the malware do if it determine it is running in a debugger?

Answer:
- QueryPerformanceCounter: It changes the value of a char that is used to deocde the value of the filename.
- Filename Check: It exits if the filename don't matches the expected.
- GetTickCount: If it fails then it causes an exception at 0x4015B4.

<img src="/assets/img/lab16/3exce.png">

- rdtsc: If this check fails then the malware delete itself.

> Question 6: Why are the anti-debugging techniques successful in this malware?

Answer: The anti-debugging timing checks are successful because the malware causes and catches an exception that it handles by manipulating the <span style="color:lightgreen">Structured Exception Handling(SEH)</span> mechanism to include its own exception handler in between two calls to the timing checking functions. Exceptions are handled much more slowly in a debugger than outside a debugger.

> Question 7: What domain name does this malware use?

Answer: "<span style="color:lightgreen">adg[.]malwareanalysisbook[.]com</span>", it can be checked by setting a breakpoint at <span style="color:lightgreen">gethostbyname</span> call.

<img src="/assets/img/lab16/3domain.png">
