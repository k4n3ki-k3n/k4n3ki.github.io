---
title: Process Injection Techniques
author: k4n3ki 
date: 2023-05-17 2:4:00 -500 
categories: [Malware] 
tags: [Tips, APIs] 
---

Identifying process injections by Windows API calls.

## <span style="color:red">Classic DLL Injection</span>
It involves injecting a dynamic-link library (DLL) into a target process, allowing the injected code to execute within the context of the process. This technique can be leveraged for various purposes, such as hooking API calls, modifying program behavior, or introducing malicious functionality.
- OPenProcess
- VirtualAllocEx
- WriteProcessMemory
- CreateRemoteThread

## <span style="color:red">DLL Injection Using SetWindowsHookEx</span>
It is a technique where a dynamic-link library (DLL) is injected into a target process by creating a hook using the SetWindowsHookEx function. This allows the injected DLL to monitor and intercept various events, such as keyboard or mouse inputs, system messages, or window-related activities.
- LoadLibrary/LoadLibraryEx
- GetProcAddress
- SetWindowsHookEx

## <span style="color:red">APC Injection</span>
APC (Asynchronous Procedure Call) injection is a technique used in Windows operating systems to inject malicious code into a target process. It involves queuing an APC to a target thread, which is a function that will be executed asynchronously at a specified time. By leveraging APC injection, an attacker can execute arbitrary code within the context of the target process, bypassing traditional security measures.
- CreateToolhelp32Snapshot
- Process32First
- Thread32First
- Thread32Next
- Process32Next
- OpenProcess
- VirtualAllocEx
- WriteProcessMemor
- QueueUserAPC/NtQueueApcThread
- VirtualFreeEx
- CloseHandle

## <span style="color:red">Atom Bombing</span>
Atom bombing is a process injection technique that allows an attacker to inject malicious code into a target process without being detected by traditional security measures. By manipulating the Atom table in Windows, the attacker can bypass security mechanisms and execute their code, posing a significant threat to system integrity and data confidentiality.

- CreateToolhelp32Snapshot
- Thread32First
- Thread32Next
- OpenThread
- CreateEvent
- DuplicateHandle
- NtQueueApcThread
- QueueUserAPC
- GetModuleHandle
- GetProcAddress
- SetEvent
- GetCurrentProcess
- SleepEx
- WaitForMultipleObjectsEx 
- MsgWaitForMultipleObjectsEx
- CloseHandle

## <span style="color:red">ALPC Injection</span>
ALPC injection involves creating a malicious thread or process that establishes a connection to the target process using ALPC. Once the connection is established, the attacker can exploit vulnerabilities or manipulate legitimate ALPC functionality to inject and execute their code within the target process. This technique allows the attacker to bypass security measures and gain control over the target process.
- NtQuerySystemlnformation
- NtDuplicateObject/ZwDuplicateObject
- GetCurrentProcess
- NtQueryObject
- NtClose
- RtllnitUnicodeString
- NtConnectPort
- VirtualAllocEx
- WriteProcessMemory
- CopyMemory
- ReadProcessMemory
- VirtualFreeEx
- VirtualQueryEx
- GetMappedFileName
- OpenProcess
- CloseHandle
- GetSystemlnfo

## <span style="color:red">LockPos</span>
Original executble loads dropper executable. Dropper injects a second stage loader and the final LockPoS payload into explorer.exe. The loader in explorer.exe loads the final LockPoS DLL.
- CreateFileMappingW
- MapViewOfFile
- RtlAllocateHeap
- NtlCreateSection
- NtMapViewOfSection
- NtCreateThreadEx

## <span style="color:red">Process Hollowing</span>
It involves creating a new instance of a legitimate process and replacing its executable image with the code of the malicious payload. This technique allows the malware to run under the context of the legitimate process, making it harder for security solutions to identify and mitigate the malicious activity.
- CreateProcess("CREATE_SUSPENDED")
- NtQueryProcesslnformation
- ReadProcessMemory
- GetModuleHandle
- GetProcAddress
- ZwUnmapViewOfSection/NtUnmapViewOfSection
- VirtualAllocEx
- WriteProcessMemory
- VirtualProtectEx
- SetThreadContext
- ResumeThread

## <span style="color:red">Process DoppelGänging</span>
It involves creating a process using transacted file operations and transactional NTFS to load and execute malicious code without leaving traces on the system. This technique manipulates the Windows loader and file system, making it difficult for traditional security solutions to detect and analyze the malicious activity.
- CreateFileTransacted
- WriteFlle
- NtCreateSection
- RollbackTransaction
- NtCreateProcessEx
- RtlCreateProcessParametersEx
- VirtualAllocEx
- WriteProcessMemory
- NtCreateThreadEx
- NtResumeThread

## <span style="color:red">Reflective PE Injection</span>
It is a technique used to inject a Portable Executable (PE) file directly into the memory of a process without the need for external modules or files. This method allows the injected code to execute within the target process while minimizing the use of traditional injection methods that could potentially raise suspicion or trigger security measures.
- CreateFileA
- HeapAlloc
- OpenProcessToken
- OpenProcess
- VirtualAlloc
- GetProcAddress
- LoadRemoteLibraryR/LoadLibrary
- HeapFree
- CloseHandle

## <span style="color:red">Thread Execution Hijacking</span>
It is a technique used to take control of the execution flow of a running thread in a process. By hijacking the execution of a thread, an attacker can divert the thread's execution to their own malicious code or manipulate the behavior of the target process.
- RtlAdjustPrivilage
- OpenProcess
- CreateToolHelp32Snapshot
- Thread32First
- Thread32Next
- CloseHandle
- VirtualAllocEx
- OpenTHread
- VirtualFree/VirtualFreeEx
- SuspendThread
- GetThreadContext
- VirtualAlloc
- WriteProcessMemory
- SetThreadContext
- ResumeThread

## <span style="color:red">Kernel Callback Table</span>
It is a sophisticated technique used by advanced attackers to manipulate the behavior of the Windows kernel by modifying or replacing entries in the kernel's callback table. The callback table contains function pointers that the kernel invokes in response to specific events or conditions.
- FindWindowA
- GetWindowThreadProcessId
- OpenProcess
- NtQueryInformationProcess
- ReadProcessMemory
- VirtualAllocEx
- WriteProcessMemory
- SendMessage
- VirtualFreeEx

## <span style="color:red">CLIPBRDWNDCLASS/Clipboard Hijacking</span>
It is a technique used to monitor and manipulate clipboard operations by injecting code into the CLIPBRDWNDCLASS window class. The clipboard window class is responsible for managing the Windows clipboard and handling clipboard-related events.
- FIndWindowEx("CLIPBRDWNDCLASS")
- OpenProcess
- VirtualAllocEx
- WriteProcessMemory
- SetProp("ClipboardDataObjectinterface")
- VirtualFreeEx

## <span style="color:red">Propagate</span>
- FindWindow("Progman")
- FindWindowEx("SHELLDLL_DefView")
- GetProp("UxSubclassinfo")
- GetWindowThreadProcessid
- OpenProcess
- ReadProcessMemory
- VirtualAllocEx
- WriteProcessMemory
- SetProp("UxSubclassinfo")
- PostMessage
- VirtualFreeEx

## <span style="color:red">Early Bird</span>
- CreateProcessA
- VirtualAloocEx
- WriteProcessMemory
- QueueUserAPC
- ResumeThread

## <span style="color:red">CONSOLEWINDOWCLASS</span>
This technique takes advantage of the window class associated with console windows to manipulate their behavior and execute arbitrary code.
- FindWIndow("ConsoleWindowClass")
- GetWindowThreadProcessId
- OpenProcess
- ReadProcessMemory
- VirtualAllocEx
- WriteProcessMemory
- VirtualFreeEx

## <span style="color:red">ToolTip Process Injection</span>
It is a technique used to inject and execute malicious code within the context of a tooltip window in Windows operating systems. This technique takes advantage of the tooltip functionality to hide and execute malicious code within a legitimate process.
- FindWindow("tooltips_class32")
- OpenProcess
- VirtualAllocEx
- WriteProcessMemory
- VirtualFreeEx
- CloseHandle

## <span style="color:red">DNS API</span>
It is a technique used to intercept and manipulate DNS (Domain Name System) queries and responses by injecting malicious code into the DNS API functions within an application or system.
- GetWindowThreadProcessId
- CreateThread
- GetTickCount
- OpenProcess
- VirtualAllocEx
- WriteProcessMemory
- VirtualFreeEx
- TerminateThread