---
title : Data Encoding(Chapter 13)
author : k4n3ki
date : 2023-06-23 1:00:00 -500
categories: [Practical Malware Analysis]
tags: [Data Encryption, Base64, KANAL, FindCrypt2]
---

These Labs are from Chapter 13(<span style="color:red">Data Encoding</span>) for practice from the book <span style="color:lightgreen">“Practical Malware Analysis”</span> written by <span style="color:lightgreen">Michael Sikorski</span> and <span style="color:lightgreen">Andrew Honig</span>.


# <span style="color:red">Lab13-01</span>

Tool used :
- Detect-it-Easy
- PEiD
- Fakenet
- x32dbg

Let's first start with static analysis by opening the exe in DiE. There are some suspicious strings like "<span style="color:lightgreen">Mozilla/4.0</span>" and "<span style="color:lightgreen">http[:]//%s/%s/</span>". It also contains a resource of lpName 0x65 and lpType 0xa.

<img src="/assets/img/lab-13/resource.png">

It imports some functions from WS2_32.dll using Ordinal.

```python
'imp_ordinal_57'(0x39) : 'imp_gethostname'
'imp_ordinal_115'(0x73) : 'imp_WSAStartup'
'imp_ordinal_116'(0x74) : 'imp_WSACleanup'
```

It also imports [InternetOpenA, InternetOpenUrlA, InternetCloseHandle, InternetReadFile] from WININET.dll. It will likely going to communicate to Command and Control server.

During basic Dynamic analysis, we can see that it tries to connect to the URL "<span style="color:lightgreen">http[:]//www[.]practicalmalwareanalysis[.]com/Z3J1ZGdl</span>".

<img src="/assets/img/lab-13/fakenetTraffic.png">

For further analysis, let's open it in IDA Pro. In main function, it calls sub_401300, in which it retrieves handle to the exe and the pointer to the resource with the help of imports. If it fails to get the handle to the exe then it prints "Could not load exe.".

> GetModuleHandleA -> FIndResourceA -> SizeofResource -> LoadResource -> LockResource

It passes the pointer and the size of resource to the function sub_401190. In sub_401190, it iterates over every byte of the resource and xor it with <span style="color:lightgreen">0x3B</span>.

<img src="/assets/img/lab-13/xorDecode.png">

Back in main function it calls WSAStartup which initiates use of the Winsock DLL by a process. If successful, it calls sub_4011C9 with decoded resource as argument. 

In sub_4011C9, it calls <span style="color:lightgreen">gethostname</span>. It copies the first 12 char of host name into Destination and passes it to function sub_4010B1 which just returns it after <span style="color:lightgreen">Base64</span> decoding. 

<img src="/assets/img/lab-13/gethostname.png">

<img src="/assets/img/lab-13/grudgebase64.png">

We can see the string "<span style="color:lightgreen">Z3J1ZGd1</span>" which appeared in fakenet. Then it formats the URL and calls the imports to connect to internet.

```
InternetOpenA -> Initializes an application's use of the WinINet functions.
InternetOpenUrlA -> Opens a resource specified by a complete FTP or HTTP URL.
InternetReadFile -> Reads data from a handle opened by the InternetOpenUrl function.
```

Then it compares the first byte recieved from the internet to "o". If equal return true else false.

If false, it runs the while loop again after a sleep call of 0x7530 milliseconds and if true, it calls WSACleanup to terminate use of the Winsock 2 DLL.

## <span style="color:red">Question and Answers</span>

> Question 1: Compare the strings in the malware(from the output of the strings command) with the information via dynamic analysis. Based on this comparison, which elements might be decoded?
<br/> Answer: In output of strings command, "http[:]//www[.]practicalmalwareanalysis[.]com/Z3J1ZGdl" seems to be missing. 

> Question 2: Use IDA Pro to look potential encoding by searching for the string xor. What type of encoding do you find?
<br/> Answer: There appear to be 18 results of xor text search in IDA Pro. Out of which 15 are zeroing xor instructions. And out of 3, 2 are from library code. The last one seems to be xoring eax with 0x3B in a loop in sub_401190.
<br/> <img src="/assets/img/lab-13/xorSearch.png">

> Question 3: What is the key used for encoding and what content does it encode?
<br/> Answer: The XOR-encoding uses 0x3B as key and it seems to be encoding the resource section of the executable.

> Question 4: Use the static tools FindCrypt2, Krypto ANALyzer(KANAL), and the IDA Entropy Plugin to idenity any other encoding mechanisms. What do you find?
<br/> Answer: PEiD KANAL plugin detect base64 encoding.
<br/> <img src="/assets/img/lab-13/kanal.png">

> Question 5: What type of encoding is used for a portion of the network traffic sent by the malware?
<br/> Answer: Base64 encoding is used to create the GET request string.

> Question 6: Where is the Base64 function in the disassembly?
<br/> Answer: sub_4010B1 is the Base64 function.

> Question 7: What is the maximum length of the Base64-encoded data that is sent? What is encoded?
<br/> Answer: It takes maximum 12 characters from the host name. So 12*4/3 = 16 will be the maximum length of Base64-encoded data.

> Question 8: In this malware, would you ever see the padding characters (= or ==) in the Base64-encoded data?
<br/> Answer: Yes, only when the length of host name is less than 12 and not divisible by 3.

> Question 9: What does this malware do?
<br/> Answer: This malware signals www[.]practicalmalwareanalysis[.]com via HTTP GET request, until it recieves 'e' as the first character of response. 


# <span style="color:red">Lab13-02</span>

Tools used:
- Detect-it-Easy
- IDA Pro
- WinHex Editor
- X32dbg
- Immdbg

For Basic static analysis, Let's open it in DiE. It contains only one interesting string, i.e. "<span style="color:lightgreen">temp%08x</span>". It imports functions from <span style="color:lightgreen">GDI32.dll</span>.

> GDI32. DLL exports Graphics Device Interface (GDI) functions that perform primitive drawing functions for output to video displays and printers.

Moving on to Basic Dynamic Analysis, We run the executable and files start appearing in the same directory as the executable. Name of these files is starting with "temp" and ending with random chars and all of them are of <span style="color:lightgreen">6.98MB</span> in size. Data of these files is unreadable, may be they encrypted.

<img src="/assets/img/lab-13/tempss.png">

Let's move to Advanced Static analysis, Open it in IDA Pro. Main function runs a infinte while loop in which it sleeps for 0x1388 milliseconds and calls sub_401851 and again sleeps for 0x1388 milliseconds before next iteration.

sub_401851 calls sub_401070 with two arguments hmem and nNumberOfBytesToWrite. Opening sub_401070, we see a bunch of WinAPI calls which are used to take a <span style="color:lightgreen">screenshot</span>.

```
GetSystemMetrics
GetDesktopWindow
GetDC
CreateCompatibleDC
CreateCompatibleBitmap
SelectObject
BitBlt
GetObjectA
GetDIBits
ReleaseDC
DeleteDC
DeleteObject
```

After screenshot taking function, sub_401851 calls another function sub_40181F with the same arguments as sub_401070. sub_40181F calls sub_401739 which contains a lot of SHR and LHR in addition to XOR instructions. It seems to be <span style="color:lightgreen">encrypting</span> the screenshot taken by the previous function.

<img src="/assets/img/lab-13/elsemain.png">

After encryption functions, sub_401851 calls <span style="color:lightgreen">GetTickCount</span> to retrieve the number of seconds passes till now into TickCount variable. Then it create a strings named Buffer equal to "temp" + TickCount. then it calls sub_401000 with hmem, nNumberOfBytesToWrite, Buffer as arguments. sub_401000 just create the file of the name temp and write the encrypted data to it.

You can decode the content using two ways:

1st: Open the malware into x32dbg and put a breakpoint on 0x401880. Follow the first address on the stack and dump it from the memory.

<img src="/assets/img/lab-13/bmpDump.png">

2nd: Open any file produced by the malware in hex editor and copy its hex data. Open the malware into x32dbg and put a breakpoint on 0x401880. Replace the data with the copied hex data from the hex editor. And continue the execution, it will decrypt the content and give it a bmp extension. 

## <span style="color:red">Question and Answers</span>

> Question 1: Using dynamic analysis, determine what the malware creates?
<br/> Answer: It creates random files of same size with name startin with temp and ending with random hex numbers.

> Question 2: Use static techniques such as an xor search, FindCrypt2, KANAL, and the IDA Entropy Plugin to look for potential encoding. What do you find?
<br/> Answer: XOR search result give potential encoding instructions in  functions sub_401739 and sub_401570.
<br/> <img src="/assets/img/lab-13/xorSearch2.png">

> Question 3: Based on your answer to question 1, which imported function would be a good prospect for finding the encoding functions?
</br> Answer: It must be encrypting the content before creating(CreateFile) and writing(WriteFile) to a file.

> Question 4: Where is the encoding function in the disassembly?
<br/> Answer: Encoding function is sub_40181F.

> Question 5: Trace from the encoding function to the source of the encoding content. What is the content?
<br/> Answer:  Content is screenshot of the desktop.

> Question 6: Can you find the algorithm used for encoding? If not, how can you decode the content?
<br/> Answer: Customized encoding algorithm is used in this malware.

> Question 7: Using instrumentation, cam you recover the original source of one of the encoded files?
<br/> Answer: Original files can be recovered bhy putting a breakpoint just before the encoding function and dump the memory containing the buffer.
<br/> Or It seems this alogrithm also decodes the content, so you can just replace the buffer in memory just before the encoding function with the encoded data produced by the malware to deocde it.
