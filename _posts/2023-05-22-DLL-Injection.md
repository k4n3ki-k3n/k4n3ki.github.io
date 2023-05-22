---
title : DLL Injection (Lab12-01)
author : k4n3ki
date : 2023-05-22 1:00:00 -500
categories: [Practical Malware Analysis]
tags: [Writeup, DLL injection]
---

It is a Lab from Chapter 12(<span style="color:red">Covert Malware Launching</span>) for practice from the book <span style="color:lightgreen">“Practical Malware Analysis”</span> written by <span style="color:lightgreen">Michael Sikorski</span> and <span style="color:lightgreen">Andrew Honig</span>.

This lab shows <span style="color:red">DLL injection</span>.

Tools Used :
- Detect-it-Easy
- IDA Pro
- Process Explorer

First start with loading the executable in Detect-it-Easy for static analysis. We see the strings like "explorer.exe", "psapi.dll", "Lab12-01.dll" and more.

<!-- <img src="exe_strings.png"> -->
![img](/exe_strings.png)

It contains imports like <span style="color:lightgreen">OpenProcess</span>, <span style="color:lightgreen">CreateRemoteThread</span>, <span style="color:lightgreen">VirtualAlloc</span>, <span style="color:lightgreen">WriteProcessMemory</span> which indicates for some kind of Process Injection.

Upon loading the DLL into Detect-it-Easy, we see that it contains some suspicious strings like "<span style="color:lightgreen">Press OK to reboot</span>", "<span style="color:lightgreen">Practical Malware Analysis %d</span>". But with static analysis we can't say anything about these strings.

During Dynamic Analysis, When we run the executable it pop up a message box every minute. There isn't any information in ProcMon, what it does and how it is doing it. Every time the number in the title of MessageBox increases.

<!-- <img src="messageBox_ss.png"> -->
![img](/messageBox_ss.png)

Taking look in Process Explorer, we can see that the DLL has been loaded into the process explorer.exe.

<!-- <img src=""> -->
![img](/procExp.png)

To know the inner working of the malware, let's load the executable in IDA Pro. Lets start with the main function. It simply loads the psapi.dll via LoadLibraryA and retrieves the addresses of functions <span style="color:lightgreen">EnumProcessModules</span>, <span style="color:lightgreen">EnumProcesses</span> via GetProcAddress.

<!-- <img src="main.png"> -->
![img](/main.png)

After that it retrieves the path of current directory and concatenate it with strings "\" and "Lab12-01.dll". Next it gets the list of PId's list of all the processes on the system through EnumProcesses. It iterates over the every element of the list and passes it to the function sub_401000.

<!-- <img src="comp_func.png"> -->
![img](/comp_func.png)

Function <span style="color:lightgreen">sub_401000</span> opens the process and and gets its module base name through GetModuleBaseNameA and compares it to "explorer.exe". If it matches then return 1 otherwise returns 0.

After returning to main function, it retrieves a handle to explorer.exe and allocates some space in the virtual address space of the process through VirtualAllocEx. Then it writes the path of the dll to this space via <span style="color:lightgreen">WriteProcessMemory</span>. And Finally it calls <span style="color:lightgreen">CreateRemoteThread</span> by passing the address of the LoadLibrary function and the address of the location that contains the path of the Lab12-01.dll. The thread that contains the DLL will run immediately after the creation.

``` cpp
HANDLE CreateRemoteThread(
  [in]  HANDLE                 hProcess, 
  // A handle to the process in which the thread is to be created
  [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes, 
  // 0 => thread gets a default security descriptor and the handle cannot be inherited
  [in]  SIZE_T                 dwStackSize, 
  // 0 => ew thread uses the default size for the executable
  [in]  LPTHREAD_START_ROUTINE lpStartAddress, 
  // A pointer to the application-defined function
  [in]  LPVOID                 lpParameter, 
  // A pointer to a variable to be passed to the thread function
  [in]  DWORD                  dwCreationFlags, 
  // 0 => The thread runs immediately after creation.
  [out] LPDWORD                lpThreadId 
  // 0 => thread identifier is not returned
);
```

Now that we know that the malware injects the DLL into explorer.exe. Lets analyse the DLL, what is does after injection. Load it into IDA Pro. Upon DLL being loaded into the process, it creates a thread and passes a function sub_10001030. 

``` cpp
switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // DLL is being loaded into a process
            // Perform initialization tasks here
            break;
        case DLL_PROCESS_DETACH:
            // DLL is being unloaded from a process
            // Perform cleanup tasks here
            break;
        case DLL_THREAD_ATTACH:
            // A new thread is being created in a process
            break;
        case DLL_THREAD_DETACH:
            // A thread is being terminated in a process
            break;
    }
```

In <span style="color:lightgreen">sub_10001030</span>, it is itrating over an infinite loop that formats a string("Practical Malware Analysis %d", i) into Parameter where i increases with every loop. It passes this string as the argument for the application-defined fuction named StartAddress while creating a new thread. It waits for a minute between every iteration of the loop.

<span style="color:lightgreen">StartAddress</span> just calls MessageBoxA with the message string "Press OK to reboot" and set the string "Practical Malware Analysis %d" as dialog box title.

## Question and Answers

```1
Question 1: What happens when you run the malware executable?
Answer: Malware start showing pop-ups on the screen after being executed.
```

```2
Question 2: What process is being injected?
Answer: explorer.exe
```

```3
Question 3: How can you make the malware stop the pop-ups?
Answer: Kill the explorer.exe from Process Explorer and restart it.
```

```4
Question 4: How does this malware operate?
Answer: The executable performs DLL injection in explorer.exe to launch Lab12-01.dll. After the launch, DLL start showing pop-ups on the screen on the interval of 1 minute.
```