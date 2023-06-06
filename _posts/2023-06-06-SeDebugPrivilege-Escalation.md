---
title : SeDebugPrivilege Escalation(Lab12-04)
author : k4n3ki
date : 2023-06-6 1:00:00 -500
categories: [Practical Malware Analysis]
tags: [Process Injection, SeDebugPrivilege Escalation]
---

These Labs are from Chapter 12(<span style="color:red">Covert Malware Launching</span>) for practice from the book <span style="color:lightgreen">“Practical Malware Analysis”</span> written by <span style="color:lightgreen">Michael Sikorski</span> and <span style="color:lightgreen">Andrew Honig</span>.

This lab shows a new technique for <span style="color:red">privilege escalation</span> and <span style="color:red">Process Injection</span>.

Tools used :
- IDA Pro
- Detect-it-Easy

During the static analysis, in Detect-it-Easy, we can see that it contains a PE file in its resource section.

<img src="resource_die.png">

In main function we can see that it gets the PiD list of all the processes running on the system through <span style="color:lightgreen">EnumProcesses</span>. It iterates over the list and passes the PiD to the function sub_401000 where it checks whether the process basename is "<span style="color:lightgreen">winlogon.exe</span>" or not. 

<img src="main.png">

Then it passes the PiD of the winlogon process as an argument to the function sub_401174. Within this function, it proceeds to call sub_4010FC, providing "<span style="color:lightgreen">SeDebugPrivilege</span>" as a parameter. This sequence aims to exploit the SeDebugPrivilege privilege by utilizing the <span style="color:lightgreen">LookupPrivilegeValueA</span> and <span style="color:lightgreen">AdjustTokenPrivileges</span> functions for privilege escalation.

Back in sub_401174, it injects a thread inside winlogon.exe and that thread is ordinal 2(<span style="color:lightgreen">SfcTerminateWatcherThread</span>) of <span style="color:lightgreen">sfc_os.dll</span>. 

> SfcTerminateWatcherThread: This function is used to disable Windows file protection and modify files that otherwise would be protected.

Back in main function, it builds two strings :
- ExistingFileName = "C:\\Windows\\system32\\wupdmgr.exe"
- NewFileName = "c:\\Windows\\Temp\\winup.exe"

Then it moves the <span style="color:lightgreen">wupdmgr.exe</span>(used for windows updates) into <span style="color:lightgreen">winup.exe</span> in temp directory. 

<img src="resource_func.png">

It calls sub_4011FC, in which it copies the resource named "#101" of type "BIN" into the wupdmgr.exe file. It launches the exe using <span style="color:lightgreen">WinExec</span> with 0 as <span style="color:lightgreen">nCmdShow</span> parameter to hide the program window.

Now to analyse the resource binary, dump it from Detect-it-Easy. In main function, it first launches the winup.exe from the Temp directory. Then it downloads a file from the url "<span style="color:red">http[:]//www[.]practicalmalwareanalysis[.]com/updater.exe</span>" to the path "C:/windows/system32/wupdmgrd.exe" and launches the file while hiding its window.

<img src="resource_main.png">


## <span style="color:red">Question and Answers</span>

> Question 1: What does the code at 0x401000 accomplish?
<br/> Answer: It checks whether the PiD belongs to winlogon.exe or not.

> Question 2: Which process has code injected?
<br/> Answer: winlogon.exe

> Question 3: What DLL is loaded using LoadLibraryA?
<br/> Answer: sfc_os.dll is loaded to disable Windows File Protection.

> Question 4: What is the fourth argument passed to the CreateRemoteThread call?
<br/> Answer: SfcTerminateWatcherThread is being passed as the 4th argument which was dynamically imported from sfc_os.dll via ordinal(2).

> Question 5: What malware is dropped by the main executable?
<br/> Answer: It drops a binary from its resource section into wupdmgr.exe(windows update binary).

> Question 6: What is the purpose of this and the droppped malware?
<br/> Answer: The malware injects a thread into winlogon.exe and calls a function SfcTerminateWatcherThread imported from sfc_os.dll to disable Windows File Protection until next reboot. The malware trojanizes wupdmge.exe with the binary present in its resource section. The dropped malware executes the Windows Update binary which was copied to the %TEMP% directory and updates itself from a URL.