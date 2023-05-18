---
title : Keylogger (Lab11-03)
author : k4n3ki
date : 2023-05-19 1:00:00 -500
categories: [Practical Malware Analysis]
tags: [Writeup, Keylogger, Trojan]
---

It is a Lab from Chapter 11(Malware Behavior) for practice from the book <span style="color:lightgreen">“Practical Malware Analysis”</span> written by <span style="color:lightgreen">Michael Sikorski</span> and <span style="color:lightgreen">Andrew Honig</span>.

This lab shows a new technique it <span style="color:red">Trojanizes</span> windows service and starts <span style="color:red">Keylogging</span>

Tools used:
- Detect-it-Easy
- Procmon
- IDA Pro
- x64dbg

We are given with <span style="color:lightgreen">Lab11-03.exe</span> and <span style="color:lightgreen">Lab11-03.dll</span> files.

First Load the exe in Detect-it_easy to examine the strings and imports. It contains interesting strings like "C:\WINDOWS\System32\inet_epar32.dll", "zzz69806582", "net start cisvc", etc.

<!-- <img src="./exe_strings.png"> -->
![img](/exe_Strings.png)

The <span style="color:lightgreen">net start</span> command is used to start a service on windows. The <span style="color:lightgreen">Content Index Service(Cisvc)</span> catalogs and tracks files on the hard drive and indexes them for faster search results. 

Next, load the DLL in DiE and we see that it has one export named "<span style="color:red">zzz69806582</span>". It contains a string "C:\WINDOWS\System32\kernel64x.dll" and imports like <span style="color:lightgreen">GetForeGroundWindow</span>, <span style="color:lightgreen">GetWindowTextA</span>, <span style="color:lightgreen">GetAsyncKeySate</span> which makes me think that it might be keylogger

> **<span style="color:lightgreen">GetForeGroundWindow</span>** -> Retrieves a handle to the foreground window (the window with which the user is currently working).

> **<span style="color:lightgreen">GetWindowTextA</span>** -> Copies the text of the specified window's title bar (if it has one) into a buffer.

> **<span style="color:lightgreen">GetAsyncKeyState</span>** -> Determines whether a key is up or down at the time the function is called, and whether the key was pressed after a previous call to GetAsyncKeyState.

Next, we try to run the executable and observe it in <span style="color:lightgreen">Procmon</span>. We see that it create "C:\WINDOWS\SysWOW64\inet_epar32.dll" and tries to open the file "C:\WINDOWS\SysWOW64\cisvc.exe" and starts the cisvc service by issuing the command "net start cisvc".

>It wasn't able to run properly, as this Windows 10 doesn't use cisvc service anymore. So i ran it on <span style="color:lightgreen">Windows XP</span>, and saw that it created "C:\WINDOWS\System32\Kernel64x.dll" which contained the key logs.

<!-- <img src="key_logs.png"> -->
![img](/key_logs.png)

For deeper understanding, load the exe in IDA Pro and start by examining the main function.

<!-- <img src="main_func.png"> -->
![img](/main_func.png)

Main function starts by copying the Lab11-03.dll into C:\WINDOWS\SysWOW64\inet_epar32.dll and next it forms a string "C:\\WINDOWS\\System32\\cisvc.exe and passes it to function sub_401070. Finally, it starts the service cisvc by passing the command "net start cisvc" to system.

Next the function sub_401070 manipulates the cisvc.exe file using the API calls(<span style="color:lightgreen">CreateFileA</span>, <span style="color:lightgreen">CreateFileMappingA</span>, <span style="color:lightgreen">MapViewOfFile</span>). After loading the cisvc.exe into IDA, we see that the entrypoint in real cisvc and modified cisvc are different. 

<!-- <img src="cisvc_comp.png"> -->
![img](/cisvc_comp.png)

So let's load the modified cisvc.exe into IDA and follow the jumps.

<!-- <img src="entry_redirection"> -->
![img](/entry_redirection.png)

Load the cisvc.exe into x64dbg and we see that it first calls LoadLibrary to load the inet_epar32.dll and then gets the address of the export function "zzz69806582" by calling GetProcAddress. Then, it calls the function and return to the actual entrypoint.

<!-- <img src="loadlib.png"> -->
![img](/loadlib.png)


Next, load the inet_epar32.dll in IDA Pro which is similar to Lab11-03.dll. Export "zzz69806582" creates a thread and return. The thread is passed with StartAddress function as <span style="color:lightgreen">lpStartAddress</span> parameter and set to run just after its creation. So, lets analyse the StartAddress function. At first it checks whether a mutex named "MZ" is exists or not. If it exists it exits and if not then it creates one. Next, it creates a file named "C:\WINDOWS\System32\kernel64x.dll" and it sets the pointer at the end of the file using API <span style="color:lightgreen">SetFilePointer</span>. 

Then it calls a function sub_10001380, which is responsible for keylogging. It contains a loop which calls an function sub_10001030 and logs the keys to the file.

<!-- <img src="sub_10001380"> -->
![img](/sub_10001380.png)

Let's see the function sub_10001030, it calls another function sub_10001000 which is responsible for getting the windows title bar of the active window through the APIs <span style="color:lightgreen">GetForeGroundWindow</span> and <span style="color:lightgreen">GetwindowTextA</span>. Then the function sub_10001030 checks which keys are being pressed using the API <span style="color:lightgreen">GetAsyncKeyState</span>.

## Questions and Answers

> Question 1: What interesting analysis leads can you discover using basic static analysis?
<br/> Answer: &emsp; Imports(GetAsyncKeyState and GetForegroundWindow) in Lab11-03.dll indecates that it might be a keylogger. Lab11-03.exe contains strings like "inet_epar32.dll" and "net start cisvc" which make us suspect that it uses cisvc service.

> Question 2: What happens when you run this malware?
<br/> Answer: &emsp; It copies the Lab11-03.dll to C:\Windows\SysWOW64\inet_epar32.dll and trojanize the cisvc.exe and starts the cisvc service. Then it creates C:\WINDOWS\System32\kernel64x.dll to log the keystrokes.

> Question 3: How does Lab11-03.exe persistently install Lab11-03.dll?
<br/>Answer: &emsp; The malware trojanize C:\WINDOWS\System32\cisvc.exe making it load inet_epar32.dll.

> Question 4: Which Windows system file does the malware infect?
<br/>Answer: &emsp; C:\WINDOWS\System32\cisvc.exe

> Question 5: What does lab11-03.dll do?
<br/>Answer: &emsp; Lab11-03.dll has an export zzz69806582 which contains all the the keylogging functionality. 

> Question 6: Where does the malware store the data it collects?
<br/>Answer: &emsp; C:\WINDOWS\System32\kernel64x.dll