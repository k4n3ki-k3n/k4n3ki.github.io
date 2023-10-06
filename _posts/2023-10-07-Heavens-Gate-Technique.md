---
title : Heaven's Gate Technique
author : k4n3ki
date : 2023-10-07 00:07:00 +530
categories: [Malware Analysis]
tags: [Malware Analysis, Reverse Engineering, Windows Internals]
---

# <span style="color:red">About</span>

The term "Heaven's Gate" in the context of Windows and the <span style="color:lightgreen">WOW64</span> (Windows on Windows 64-bit) subsystem refers to a technique used to transition from 32-bit code running in a 64-bit process to 64-bit code. This transition involves changing the processor's mode from 32-bit (x86) to 64-bit (x64). It's important to note that this technique is specific to the Windows operating system and may not be directly applicable to other platforms.

<span style="color:red">References for detailed explaintion :</span>
- https://www.mandiant.com/resources/blog/wow64-subsystem-internals-and-hooking-techniques
- http://www.hexacorn.com/blog/2015/10/26/heavens-gate-and-a-chameleon-code-x8664/
- https://www.alex-ionescu.com/closing-heavens-gate/

Here's a detailed explanation of how the Heaven's Gate technique works and how it changes the CS (Code Segment) register:

## <span style="color:red">Background:</span>
- In a 64-bit Windows environment, you can run both 32-bit and 64-bit applications. However, these two types of applications have different instruction sets and operate in different processor modes.
- 32-bit applications run in the compatibility mode of the 64-bit processor and use 32-bit registers and instructions.
- 64-bit applications run natively in 64-bit mode and use 64-bit registers and instructions.


## <span style="color:red">The CS Register:</span>
- In x86 architecture, the CS (Code Segment) register holds the segment selector for the code segment. It plays a crucial role in determining the current execution mode of the processor.
  
> cs register value: for x86 : 0x23, x64 : 0x33

- The CS register contains information about the current privilege level (Ring 0 for kernel mode and Ring 3 for user mode) and the code segment's base address.

## <span style="color:red">Heaven's Gate Technique:</span>
- When a 32-bit application running within a 64-bit process needs to call a 64-bit system function or interface, it must switch the processor into 64-bit mode. This is where the Heaven's Gate technique comes into play.
- The technique involves executing a special syscall instruction, which triggers a context switch from 32-bit mode to 64-bit mode, effectively changing the CS register's contents.

## <span style="color:red">Context Switch:</span>
- The Windows kernel handles the transition between modes. It saves the state of the 32-bit execution environment, including the CS register, before switching to 64-bit mode.
  
> It uses push and far ret instructions for this purpose.

> When executing a far return, the processor pops the return instruction pointer from the top of the stack into the EIP register, then pops the segment selector from the top of the stack into the CS register.

- In 64-bit mode, the code within the Windows kernel or the target 64-bit function is executed.
- After completing the 64-bit operation, another context switch is performed to return to the 32-bit mode, restoring the saved state, including the original value of the CS register.

## <span style="color:red">Usage:</span>
- Heaven's Gate is typically used when a 32-bit application needs to access 64-bit system libraries or interfaces that are not available in 32-bit mode.
- This technique allows 32-bit applications to leverage the capabilities of the 64-bit operating system without having to run as separate processes.

In summary, Heaven's Gate is a technique used in Windows (WOW64) to transition from 32-bit code to 64-bit code by changing the processor's mode from x86 to x64. It involves a context switch managed by the Windows kernel, which saves and restores the state of the CS register and other relevant registers to ensure a smooth transition between the two modes, enabling 32-bit applications to interact with 64-bit system components when needed.

# <span style="color:red">Crackme</span>

## <span style="color:red">Info :</span>
- Author : yyk
- Language : C/C++
- Platform : Windows
- Difficulty : 3.0
- Arch : x86

Description: This contains heaven's gate. You should get KEY from 64bit area.

You can download the crackme from [here](https://crackmes.one/crackme/63b15b5333c5d43ab4ecf226).

## <span style="color:red">Walkthorough</span>

Lets upload the binary in <span style="color:lightgreen">DiE</span>, where we can see that it contains a lot strings and imports from VCRUNTIME140D.dll, ucrtbased.dll, <span style="color:lightgreen">KERNEL32.dll</span>.

[Capa](https://github.com/mandiant/capa) detect that it is using Heavens Gate for Defense Evasion. 

<img src="/assets/img/heaven/capa.jpg">

It just asks for a key and prints "wrong" if the the key is incorrect.

<img src="/assets/img/heaven/run.jpg">

In IDA Pro, we can see that it is having problem disassembling the function in which this technique is used. As retf is used to change the value of cs register that confuses IDA to define the function.

<img src="/assets/img/heaven/ida.jpg">

Lets load the binary in x32dbg, and run the input to see where it is being stored. Afteer running the binary completely and passing the input we can go to the "Find Strings" section and see the input.

<img src="/assets/img/heaven/strings.jpg">

Put a access hardware breakpoint on the address where the input is being stored. Follow the address in dump. Right click on the first byte of input and select <span style="color:lightgreen">Breakpoint -> Hardware, Access -> Byte</span>. Now, restart the debugger, pass the input, it will break at 0x00FB17EB.

<img src="/assets/img/heaven/breakpoint.jpg">

Now, we can go through the instructions and see how the technique is used.

<img src="/assets/img/heaven/ret.jpg">

- First <span style="color:lightgreen">0x33</span> is pushed on the stack.
- At 0x00FB17F3, it calls the next instruction(0x00FB17F8) and the call instruction will push the address 0x00FB17F8 on the stack.
- Then, it adds 5 to the address stored at esp(0x00FB17F8 + 5 = 0x00FB17FD).
- It calls "<span style="color:lightgreen">ret fat</span>", which will pop two values from the stack, first into EIP and second into CS register, which causes the switch.

x32dbg crashes after the "ret far" instruction, so we will have to go through the assembly to find out the key.

> **NOTICE** one thing that at 0x00FB17D1, it first pushes 00 and then at next instruction it pushes ecx. And down the code, it just pop the values from stack and compares them. Reason behind is that after the switch to x64, the size of the values popping from the stack will be 8 bytes.

To get the key, we will have to disassemble the instruction according to x64 processor. To do that just copy the bytes between the "ret far" instructions and save them to a file and load that file into IDA64. We can see the change in the instructions.

<img src="/assets/img/heaven/cmp.jpg">

We can find the key easily, as it's just comparing the charactres of the key one by one. Finaly the key is "**h34vEn**".

In essence, the Heaven's Gate technique involves the use of a specific segment call gate to switch between 32-bit and 64-bit processor modes within the WoW64 environment, with implications for both legitimate and potentially malicious purposes related to software compatibility and security.
