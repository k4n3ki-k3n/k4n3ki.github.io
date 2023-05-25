---
title : Process Replacement & Hook Injection
author : k4n3ki
date : 2023-05-25 1:00:00 -500
categories: [Practical Malware Analysis]
tags: [Process Replacement, Hook Injection, Keylogger]
---

These Labs are from Chapter 12(<span style="color:red">Covert Malware Launching</span>) for practice from the book <span style="color:lightgreen">“Practical Malware Analysis”</span> written by <span style="color:lightgreen">Michael Sikorski</span> and <span style="color:lightgreen">Andrew Honig</span>.

These Labs Lab12-02 & Lab12-03 shows new techniques knwon as Process Replacement & Hook Injection. 

Tools used :
- Detect-it-Easy
- Process Explorer
- Procmon
- IDA Pro
- x32dbg

For static analysis, i loaded the executable into Detect-it-Easy. It contains a resource section named "<span style="color:lightgreen">LOCALIZATION</span>" of type "<span style="color:lightgreen">UNICODE</span>". The resource doesn't seem to be PE file as it doesn't contain the "MZ" identifier or "this program cannot be run in dos mode". It imports functions for resource manipulation(FindResourceA, SizeofResource, LoadResource, LockResource), memory manipulation(WriteProcessMemory, ReadProcessMemory, VirtualAlloc), thread manipulation(GetThreadContext, SetThreadContext, ResumeThread), etc.

<img src="/assets/img/Lab12-02/resource_section.png">
<!-- ![img](/resource_section.png) -->

So, Let's move to Dynamic analysis, open Procmon and Process Explorer before running the executable. Set filters in Procmon by Process name being "Lab12-02.exe". Execute the Lab12-02.exe and we see that it creates <span style="color:lightgreen">svchost.exe</span>. The svchost.exe creates <span style="color:lightgreen">practicemalwareanalysis.log</span>. Opeining which we can see that it logged the keystrokes.

<img src="/assets/img/Lab12-02/logFile.png">
<!-- ![img](/logFile.png) -->

We try to look svchost.exe in Process Explorer, and tried to compare the string in <span style="color:lightgreen">image</span> and <span style="color:lightgreen">memory</span>, which differed significantly. We can see that svchost.exe contains key names and the filename which was created.

<img src="/assets/img/Lab12-02/comp.png">
<!-- ![img](/comp.png) -->

Let's move to Advanced static analysis and load the exectable in IDA Pro. In main function, it retrieves a handle to the executable. It calls a function sub_40149D, which gets the system directory path and concatenates it with "\\svchost.exe".

<img src="/assets/img/Lab12-02/main_func.png">
<!-- ![img](/main_func.png) -->

Then it calls another function <span style="color:lightgreen">sub_40132C</span>, Which gets a handle to the resource section through <span style="color:lightgreen">FindResourceA</span> and gets a pointer that points to the first byte of resource section though <span style="color:lightgreen">LockReosurce</span>. Then allocates some memory section and copies the resource section to that memory. It compares the first two of the resource section to "MZ", if not matches then it passes the memory section to a function sub_401000. 

<img src="/assets/img/Lab12-02/resource_function.png">
<!-- ![img](/resource_function.png) -->

In function <span style="color:lightgreen">sub_401000</span>, it xor every byte of the resource section to 65. After xoring the section, we can see strings like "MZ", "This program cannot be run in DOS mode.". It returns the memory section.

<img src="/assets/img/Lab12-02/resource_decode.png">
<!-- ![img](/resource_decode.png) -->

The last remaining function <span style="color:lightgreen">sub_4010EA</span> seemed compilcated whose parameters are the svchost.exe path and a buffer that contains the resource section's content. It compares the first two strings of buffer with "<span style="color:lightgreen">MZ</span>" and at offset of 0x3c with "<span style="color:lightgreen">PE</span>".

> PE files contains the string "PE" at offset 0x3C, meanwhile PE+ files at 0xE0.

After that it creates a process of name svchost.exe in suspened state using CreateProcessA. Then it allocates some memory in Lab12-02.exe for LPCONTEXT structure and set <span style="color:lightgreen">lpcontext->CONTEXTFLAGS = 65543</span> and retrieves the context of the thread via <span style="color:lightgreen">GetThreadContext</span>.

```
The value 65543 is a combination of the following context flags:
- CONTEXT_FULL: This flag specifies that the entire context record should be filled in.
- CONTEXT_INTEGER: This flag specifies that the integer registers should be filled in.
- CONTEXT_FLOATING_POINT: This flag specifies that the floating-point registers should be filled in.
- CONTEXT_EXTENDED: This flag specifies that the extended registers should be filled in.
```

Then it reads the process memory via <span style="color:lightgreen">ReadProcessMemory</span> and Unmap the section buffer where it read the memory via dynamically loaded <span style="color:lightgreen">NtUnmapViewOfSection</span>. It allocates memory and writes the resource section content to it via <span style="color:lightgreen">WriteProcessMemory</span> and sets the context by calling <span style="color:lightgreen">SetThreadContext</span> and resumes the process thread via <span style="color:lightgreen">ResumeThread</span>.

<img src="/assets/img/Lab12-02/write.png">

So, sub_4010EA replaces the svchost.exe with the decoded resource section of Lab12-02.exe. 

Now, we can move to Advanced dynamic analysis to dump the decoded resource section. Load the exe in x32dbg and set a breakpoint at call to SetThreadContext and follow the second parameter to dump, and we can see the PE file there. Right click on the address and follow in memory map and save the dump memory to file.

<img src="/assets/img/Lab12-02/dump.png">

## <span style="color:red">Keylogger Analysis</span>

When we load the saved binary to Detect It Easy, we can see that it is a PE32 file. In strings section, we can see the same strings that we saw in the memory of svchost.exe during dynamic analysis.

<img src="/assets/img/Lab12-02/key_strings.png">

When we look for imports, we see some functions that indicates(GetForeGroundWindow, GetWindowTextA) for a keylogger though we already knwo that from our dynamic analysis of Lab12-02.exe.

<img src="/assets/img/Lab12-02/key_imports.png">

Lets load the bin file into IDA Pro. In main function, it allocates a new console window for the calling process and set its show state to hidden. Then it installs a hook procedure that monitors low-level keyboard input events. Then it calls a while loop to retreive messages from all the windows and threads. After that it removes the hook procedure.

<img src="/assets/img/Lab12-02/key_main.png">

Lets analyse the <span style="color:lightgreen">hook procedure</span> named "<span style="color:lightgreen">fn</span>". It contains three parameters. The function first checks the code parameter. If the code is <span style="color:lightgreen">HC_ACTION(0)</span>, then the function checks the <span style="color:lightgreen">wParam</span> parameter. If the wParam parameter is <span style="color:lightgreen">WM_SYSKEYDOWN</span> or <span style="color:lightgreen">WM_KEYDOWN</span>, then the function calls the function sub_4010C7. Then calls <span style="color:lightgreen">CallNextHookEx</span> to pass the hook information to next hook procedure.

<img src="/assets/img/Lab12-02/fn.png">

In <span style="color:lightgreen">sub_4010C7</span>, it creates a file named "<span style="color:lightgreen">practicalmalwareanalysis.log</span>". It sets the pointer to the current-end of the file via <span style="color:lightgreen">SetFilePointer</span>. Then it stores the windows title text of the window with which user is currently working in str2 using <span style="color:lightgreen">GetForeGroundWindow</span> and <span style="color:lightgreen">GetWindowTextA</span>. Then it writes a string("[Window : " + str2 + "]") in the log file. Then it stores the keyboard values in the file.

<img src="/assets/img/Lab12-02/keylog_func.png">

## <span style="color:red">Lab12-02 Question & Answers</span>

> Question 1: What is the purpose of this program? </br>
> Answer : Purpose of this program is to launch an keylogger.

> Question 2: How does the launcher program hide execution? </br>
> Answer : The program performs process replacement on svchost.exe.

> Question 3: Where is the malicious payload stored? </br>
> Answer : The malicious payload is stored in the resource section of the executable and has type "UNICODE" and named "LOCALIZATION".

> Question 4: How is the malicious payload protected? </br>
> Answer : The malicious payload is XOR-encoded to 0x41 in resource section.


## <span style="color:red">Lab12-03 Question & Answer</span>

> Question 1: What is the purpose of this malicious payload? </br>
> Answer : The purpose of malicious payload is to log the keystrokes and the active window title text.

> Question 2: How does the malicious payload inject itself? </br>
> Answer : The malicious payload uses hook injection.

> Question 3: What filesystem residue does this program create? </br>
> Answer : It creates a practicalmalwareanalysis.log file in the same directory of Lab12-02.exe.
