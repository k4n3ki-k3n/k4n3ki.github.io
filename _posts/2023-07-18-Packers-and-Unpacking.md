---
title : Packers and Unpacking(Chapter 18)
author : k4n3ki
date : 2023-07-18 1:00:00 -500
categories: [Practical Malware Analysis]
tags: [Packing/Unpacking, Debugging]
---

These Labs are from Chapter 18(<span style="color:red">Packers and Unpacking</span>) for practice from the book <span style="color:lightgreen">“Practical Malware Analysis”</span> written by <span style="color:lightgreen">Michael Sikorski</span> and <span style="color:lightgreen">Andrew Honig</span>.


Tools used:
- Detect-It-Easy
- CFF Explorer
- IDA Pro
- x64Dbg

> Your goal for the labs in this chapter is simply to unpack the code for further analysis. For each lab, you should try to unpack the code so that other static analysis techniques can be used. While you may be able to find an automated unpacker that will work with some of these labs, automated unpackers won’t help you learn the skills you need when you encounter custom packers. Also, once you master unpacking, you may be able to manually unpack a file in less time than it takes to find, download, and use an automated unpacker.
<br/> Each lab is a packed version of a lab from a previous chapter. Your task in each case is to unpack the lab and identify the chapter in which it appeared. The files are Lab18-01.exe through Lab18-05.exe.

## <span style="color:red">Lab 18-01</span>

After opening the executable in DiE, we can see that it detected that it is packed by modified <span style="color:lightgreen">UPX</span>.

<img src="/assets/img/lab18/1die.png">

Seeing the sections in CFF Explorer, we can see that it contains a section named "UPX2".

<img src="/assets/img/lab18/1cff.png">

So let's open the malware in IDA Pro to see the jump to OEP. IDA too gives a warning that this program may be packed while loading the binary.

<img src="/assets/img/lab18/1idawarning.png">

IDA Pro red marked a jump instruction because it couldn't disassemble the packed data.

<img src="/assets/img/lab18/1idajmp.png">

To unpack it we just have to put a breakpoint at this jmp instruction and follow it, we will be able to reach the OEP.

<img src="/assets/img/lab18/1bp.png">

We can see that the jmp instruction is followed by NULL bytes. After single-stepping the jmp instruction, we reach the OEP.

<img src="/assets/img/lab18/1scylla.png">

By using the x32dbg plugin <span style="color:lightgreen">Scylla</span>, we can get the imports and dump the unpacked binary.

> We can find the tail jump by an another way too. Apply a hardware breakpoint at the esp location where it pushes the first bytes at entrypoint.

After going through the unpacked binary, we identified that this is the sample executable from Lab14-01.

## <span style="color:red">Lab 18-02</span>

DiE detected that it is packed by <span style="color:lightgreen">FSG(1.0)</span>. It don't contain any strings and only 2 imports(GetProcAddress, LoadLibraryA).

<img src="/assets/img/lab18/2die.png">

IDA Pro gave a warning while opening this binary.

<img src="/assets/img/lab18/2idawarning.png">

In IDA, we could see a reference of dword_401090 at 0x4050E1. Other than this we see a red marked instruction at address 0x40508E.

Load the binary in OllyDbg, it stops at 0x405000. We can identify the OEP by using the <span style="color:lightgreen">OllyDump</span> plugin. **Plugins -> OllyDump -> Find OEP by Section Hop(Trace over)**. It will stop the execution at 0x401090, but we can't see the disassembled instruction at this section. 

<img src="/assets/img/lab18/2trace.png">

TO force the OllyDbg to disassemble this code, right click at the byte at 0x401090 and select **Analysis -> Analysis code**.

<img src="/assets/img/lab18/2code.png">

You can dump the unpacked malware using **Plugins -> OllyDump -> Dump Debugged Process**.

<img src="/assets/img/lab18/2dump.png">

Now, we can see all kind of information(imports, strings) in this unpacked malware. Going through this malware reveals that it is the same executable as Lab07-2.exe.


## <span style="color:red">Lab 18-03</span>

In DiE, we can see that is is packed by <span style="color:lightgreen">PECompact(1.68-1.84)</span>. It contains a few strings and imports.

<img src="/assets/img/lab18/3die.png">

IDA Pro gave warning while opening the malware in it.

<img src="/assets/img/lab18/3idawarning.png">

IDA only identified two functions which doesn't give much insight about the tail jump and packing stub.

<img src="/assets/img/lab18/3ida.png">

SO, let's load the binary in x64dbg where it stops the execution at system breakpoint at 0x76F41C33 in ntdll region. It also sets one time breakpoint at 0x405130. **Set a read breakpoint on the stack** approach, we see a pushad instruction at 0x405139.

<img src="/assets/img/lab18/3pushad.png">

To set a read breakpoint on the stack, left click on the esp when eip reaches 0x40513A. Choose **Breakpoint -> Hardware, Access -> Dword**. After resuming the execution, debugger hit the breakpoint at 0x40754F on popfd instruction. Under which we see that it pushes an address to stack and return to it.

<img src="/assets/img/lab18/3ret.png">

We have found the tail jump and following which we reached the unpacked entrypoint. Usin Scylla, we dump the unpacked malware. 

<img src="/assets/img/lab18/3dump.png">

After going through the unpacked malware, we recognise that it is the same sample from Lab09-02.


## <span style="color:red">Lab 18-04</span>

DiE detected that this binary is packed by <span style="color:lightgreen">ASPack(2.12-2.42)</span> packer. We can see that it contains three imports from kernel32.dll and one import from other DLLs.

<img src="/assets/img/lab18/4die.png">

IDA gives a warning about the destroyed imports segment. IDA was able to identify/disassemble only one function.

<img src="/assets/img/lab18/4ida.png">

In book, Author has mentioned the technique to unpack any malware packed by ASPack. So, let's load the executable in x64dbg, where it stops the execution at system breakpoint 0x76F41C33. Resuming the execution, it again breaks at 0x411001, which is entry point to the packing stub. The instruction at 0x411001 is **pushad**. Step over this instruction and put a read hardware breakpoint on the stack. After reaching 0x411002, left click on stack top address and choose **Breakpoint -> Hardware, Access -> Dword**.

<img src="/assets/img/lab18/4stack.png">

Resuming the execution, it break at 0x4113B0, where it push the address 0x403896 and return to it.

<img src="/assets/img/lab18/4ret.png">

0x403896 is the Original Entry point to the unpacked malware. Using Scylla, we can dump the unpacked sample.

Going through the malware, we can see that it the same sample as Lab09-01.exe.

## <span style="color:red">Lab 18-05</span>

Die detected that this malware is packed by <span style="color:lightgreen">(Win)Upack(0.39 final)</span>. It doesn't contain any strings and imports.

<img src="/assets/img/lab18/5die.png">

IDA Pro gives all kinds of warning about unaligned section pointers, truncated section, translation for relative address, destroyed imports segment. IDA identified only start function which ends with jmp instruction. 

<img src="/assets/img/lab18/5jmpida.png">

I thought this is the tail jump, so i loaded the malware into x64dbg and put a breakpoint on 0x408D6E. But after some iterations, we can see it unpacking the malware in dump from address 0x401000.

In book, author has mentioned that, to unpack malware packed by WinUpack, put a breakpoint at <span style="color:lightgreen">GetCommandLineA</span> and the OEP should be above it.

So i put the breakpoint at GetCommandLineA, and restarted the debugger. We hit the breakpoint at 0x75FD2580, we run to user code and reach at address 0x40120A. Scrolling above, we can see **push ebp** instruction at 0x401191 which seems to be the entrypoint.

<img src="/assets/img/lab18/5oep.png">

Now, Dump the unpacked malware using Scylla.

Going through the unpacked malware, we can see that this sample is from Lab07-01.
