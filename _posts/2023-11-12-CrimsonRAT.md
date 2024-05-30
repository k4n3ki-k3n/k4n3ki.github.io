---
title : CrimsonRAT
author : k4n3ki
date : 2023-11-12 00:07:00 +530
categories: [Malware Analysis]
tags: [Trojan, .Net malware]
---


# <span style="color:red">Content</span>
- [IOCs](#iocs)
- [Static Anaylsis](#static-anaylsis)
    - [Virustotal report](#virustotal-report)
    - [File Metadata](#file-metadata)
    - [Capa](#capa)
- [Advanced Static & Dynamic Anaylsis](#advanced-static--dynamic-anaylsis)
    - [DnSpy](#dnspy)
    - [Localhost mapping](#localhost-mapping)
    - [Read data from server](#read-data-from-server)
    - [Capabilities](#capabilities)
        - [Send Image to Server](#send-image-to-server)
        - [Launcher](#launcher)
        - [Retrieve process list and ID](#retrieve-process-list-and-id)
        - [Delete File](#delete-file)
        - [set Registry](#set-registry)
        - [Desktop Screenshot](#desktop-screenshot)
        - [Drives name](#drives-name)
        - [Retrieve file Metadata](#retrieve-file-metadata)
        - [Create File](#create-file)
        - [Create file and execute](#create-file-and-execute)
        - [Read File](#read-file)
        - [Get list of Sub-Directories](#get-list-of-sub-directories)
        - [host Info](#host-info)
- [Conclusion](#conclusion)
    - [MITRE ATT&CK Tactic and Technique](#mitre-attck-tactic-and-technique)
    - [network indicators](#network-indicators)


# <span style="color:red">IOCs</span>

- **MD5**: 59211a4e0f27d70c659636746b61945a
- **SHA256**: 2110af4e9c7a4f7a39948cdd696fcd8b4cdbb7a6a5bf5c5a277b779cc1bf8577
- **Malware Sample**: https://bazaar.abuse.ch/sample/ce556d55e07bf6b57e3e086e57e9c52552ac7f00adf4a7c9f99bbc21a5ac26c2/

# <span style="color:red">Static Anaylsis</span>

## <span style="color:red">Virustotal report</span>

Starting by searching the hash on VirusTotal, I found that 29 out of 70 vendors flagged this binary as malicious. According to the VirusTotal report, it contacts 4 URLs, 8 IPs, and 6 domains.

<img src="/assets/img/assignment/virustotal.jpg">

## <span style="color:red">File Metadata</span>

Beginning the static analysis with <span style="color:lightgreen">DiE</span>, we can observe that it is a .NET binary and appears to be a recently compiled one.

<img src="/assets/img/assignment/die.jpg">


It appears that the binary is obfuscated or packed. I attempted to deobfuscate the sample using <span style="color:lightgreen">de4dot</span> and <span style="color:lightgreen">NetReactorSlayer</span>, but there was no noticeable change in the code.

Furthermore, DiE reported that the .text section is also packed, as its entropy is 7.58. This section contains various resources, such as icons, version information, and the manifest.

<img src="/assets/img/assignment/entropy.jpg">

## <span style="color:red">Capa</span>

 Next, I used <span style="color:lightgreen">Capa</span> to identify its capabilities. The following capabilities were identified, and we will explore them during the debugging process.

<img src="/assets/img/assignment/capa.jpg">


# <span style="color:red">Advanced Static & Dynamic Anaylsis</span>

## <span style="color:red">DnSpy</span>

If we inspect the code using DnSpy, within <span style="color:lightgreen">Form1</span>, there's a method named <span style="color:lightgreen">Form1_Load</span> which calls another method called <span style="color:lightgreen">corediQart</span>. In this method, we can see a <span style="color:lightgreen">Timer</span> being set to call a method named <span style="color:lightgreen">procvQloop</span> at specific intervals.

<img src="/assets/img/assignment/timer.jpg">

This TimerCallback will execute the <span style="color:lightgreen">procvQloop</span> method at intervals of approximately 1 minute. Inside procvQloop, a <span style="color:lightgreen">TCPClient</span> object is created to establish a connection to the server. Subsequently, it calls a method called <span style="color:lightgreen">systeWons</span>.

<img src="/assets/img/assignment/procvQloop.jpg">

<span style="color:lightgreen">systeWons</span> retrieves the <span style="color:lightgreen">min_codns</span> IP address and attempts to establish a connection to the server at "<span style="color:lightgreen">162.245.191.217</span>" on port <span style="color:lightgreen">9149</span>. 

<img src="/assets/img/assignment/ippython.jpg">

If it successfully connects, it returns true. If the connection fails, it attempts to connect to other ports[9149, 15198, 17818, 27781, 29224].

<img src="/assets/img/assignment/systewons.jpg">


## <span style="color:red">Read data from server</span>

After establishing a connection to the server in <span style="color:lightgreen">systeWons</span>, <span style="color:lightgreen">procvQloop</span> proceeds to call another method named <span style="color:lightgreen">procD_core</span>. Inside procD_core, an object of <span style="color:lightgreen">NetworkStream</span> is created, and it subsequently calls the <span style="color:lightgreen">get_procsQtype</span> method.

<img src="/assets/img/assignment/procD_core.jpg">


In the <span style="color:lightgreen">get_procQtype</span> method, it reads 5 bytes from the server, which are used as the size of the remaining buffer. It then reads the remaining buffer using for loop. This data is converted into a string and returned after splitting it by the <span style="color:lightgreen">"="</span> character.

<img src="/assets/img/assignment/get_procsQtype.jpg">


<span style="color:lightgreen">get_procsQtype</span> return <span style="color:lightgreen">process_type</span> containing two strings. 

<img src="/assets/img/assignment/buffer.jpg">

Now, it performs split, remove, and insert operations on process_type[0]. Taking the example of the above data, the text will be updated as follows:

- "-ruy1nf" (Split) -> "ruy1nf"
- "ruy1nf" (Remove) -> "ruynf"
- "ruynf" (Insert) -> "ruyTf"

So, the final result is "ruyTf".


```c#
string text = procss_type[0].ToLower();
if (text.Split(new char[] { '-' }).Length > 1)
{
	text = text.Split(new char[] { '-' })[1];
}
text = text.Remove(3, 1);
text = text.Insert(3, "T");
```

Following these text manipulation operations in <span style="color:lightgreen">procD_core</span>, the resulting text is then compared to a set of strings to determine and perform specific tasks accordingly based on the comparison results.


## <span style="color:red">Localhost mapping</span>

To understand how the data is being formatted and how it executes based on the data, I proceeded with debugging. However, an exception was thrown because the malware failed to connect to the server. To resolve this issue, I mapped the IP from the malware to localhost using the following command.

> netsh int ip add address "Loopback" 162.245.191.217

For further analysis, I initiated a Python server.

```python 
import socket			 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)		 
print ("Socket successfully created")

port = 9149			
s.bind(('', port))		 
print ("socket binded to %s" %(port)) 

s.listen()	 
print ("socket is listening")		 

while True:  
    c, addr = s.accept()	
    print("accepted")

    c.send(b'\x28\x00\x00\x00\x00-ruy1nf=C:\\Windows\\system32\\notepad.exe>') 
    c.close()
    break
```

## <span style="color:red">Capabilities</span>

It depends on a keyword that is checked in procD_core for further execution.

### <span style="color:red">Send Image to Server</span>

To call the <span style="color:lightgreen">imagiQtails</span> function and pass the required argument, you should provide the following data:

> keyword : thyTumb

> command : "\x84\x00\x00\x00\x00-thyTumb=C:\Users\vboxuser\Desktop\c46-FirstHack\assignment\ce556d55e07bf6b57e3e086e57e9c52552ac7f00adf4a7c9f99bbc21a5ac26c2\car.jpg"

In the following image, we can see that the path of the image will be passed to imagiQtails.

<img src="/assets/img/assignment/sscall.jpg">

<span style="color:lightgreen">ImagiQtails</span> passes three arguments to the function <span style="color:lightgreen">loadQdata</span>. These arguments are:
- A stream containing the image bytes.
- File metadata
- A boolean value.

loadQdata writes array3 to NetworkStream, where array3 = sizeof(file metadata) + file metadata + sizeof(image bytes) + image bytes.

<img src="/assets/img/assignment/ssListen.jpg">

In the picture above, it is evident that after formatting the data, it writes the data to a network stream, and we receive it on the Python server.

### <span style="color:red">Launcher</span>

> Keyword : ruyTnf

> command : "\x28\x00\x00\x00\x00-ruyTnf=C:\Windows\system32\notepad.exe"

If we pass <span style="color:lightgreen">"\x28\x00\x00\x00\x00-ruy1nf=C:\Windows\system32\notepad.exe"</span>, the malware will start notepad.exe.

We can observe the variables in the above screenshot. The argument is being split into parts as shown below:

```
size: "\x28\x00\x00\x00\x00"
process_type: ["-ruy1nf", "C:\\Windows\\system32\\notepad.exe>"]
```

<img src="/assets/img/assignment/processStartDBG.jpg">

> process_type[1].Split(new char[] {'>'})[0] = "C:\\Windows\\system32\\notepad.exe"

In the above screenshot, "C:\Windows\system32\notepad.exe" is being passed to the <span style="color:lightgreen">Process.Start</span> method to initiate the execution of notepad.exe.


### <span style="color:red">Retrieve process list and ID</span>

> Keyword : geyTtavs || pryTocl

> Command : "\x09\x00\x00\x00\x00-geyTtavs"

If the malware receives the above command from the server, it will invoke the <span style="color:lightgreen">machine_process</span> method. This method will retrieve the list of processes running on the host and send this information to the server, including their respective process IDs.

<img src="/assets/img/assignment/machineProcess.jpg">


### <span style="color:red">Delete File</span>

> Keyword : deyTlt

> Command : Size + "-" + deyTlt + "=" + filePath

<img src="/assets/img/assignment/delete.jpg">

The trasQfiles method takes a file path as an argument and deletes the specified file. This method will ne initiated by procD_core.

### <span style="color:red">set Registry</span>

> Keyword : puyTtsrt

> command : "\x09\x00\x00\x00\x00-puyTtsrt"


<img src="/assets/img/assignment/regset.jpg">

The set_coruep method adds the current executable path to the Windows Registry key "<span style="color:lightgreen">SOFTWARE\Microsoft\Windows\CurrentVersion\Run</span>" This allows the malware to run automatically every time the user logs in.


### <span style="color:red">Desktop Screenshot</span>

> Keyword : scyTuren || scyTren || scyuTren || scyrTen

> Command : \x0e\x00\x00\x00\x00-cdyTcrgn=100>

<img src="/assets/img/assignment/image.jpg">

<span style="color:lightgreen">deskWcren</span> takes a parameter to determine what percentage of the screen should be captured.

### <span style="color:red">Drives name</span>

> Keyword : diyTrs

> Command : \x07\x00\x00\x00\x00-diyTrs

<img src="/assets/img/assignment/drives.jpg">

loawthudrive method get the names of all the drives present in the host.

<img src="/assets/img/assignment/drivecmd.jpg">


### <span style="color:red">Retrieve file Metadata</span>

> Keyword : fiyTlsz

> Command : \x85\x00\x00\x00\x00-fiyTlsz=C:\\Users\\vboxuser\\Desktop\\c46-FirstHack\\assignment\\ce556d55e07bf6b57e3e086e57e9c52552ac7f00adf4a7c9f99bbc21a5ac26c2\\test.txt

<img src="/assets/img/assignment/metadata.jpg">

It returns a string consisting of the file name, creation time, and size.



### <span style="color:red">Create File</span>

> Keyword : doyTwr

> Command : \x2b\x00\x00\x00\x00-doyTwr=C:\\Users\\vboxuser\\Desktop\\suraj.txt\x0a\x00\x00\x00\x00Surajyadav

<img src="/assets/img/assignment/filecreate.jpg">

First, it reads the keyword and the file path to create. In <span style="color:lightgreen">doviruAfile</span>, it calls <span style="color:lightgreen">downQdata</span>, which reads the content to be written to the file. 

The command above created a file on the Desktop named 'suraj.txt' containing 'Surajyadav.'

### <span style="color:red">Create file and execute</span>

> Keyword : udyTlt

> Command : \x07\x00\x00\x00\x00-udyTlt + sizeof(file data) + file data

<img src="/assets/img/assignment/filecreatestart.jpg">

```c#
public static string del_account = "rtwihri_b".Replace("_", "");
```

The '<span style="color:lightgreen">downQdata</span>' function reads file data from a network stream, while the '<span style="color:lightgreen">get_apriath</span>' function returns the directory path of the malware. The script will then create a file named '<span style="color:lightgreen">rtwihrib.exe</span>' and write the data into it. Finally, '<span style="color:lightgreen">Process.Start</span>' is used to execute it.




### <span style="color:red">Read File</span>

> Keyword : fiyTle

> Command : \x83\x00\x00\x00\x00-fiyTle=C:\\Users\\vboxuser\\Desktop\\c46-FirstHack\\assignment\\ce556d55e07bf6b57e3e086e57e9c52552ac7f00adf4a7c9f99bbc21a5ac26c2\\car.jpg

<img src="/assets/img/assignment/readfile.jpg">

<span style="color:lightgreen">movQfiles</span> sends the requested file back to server.



### <span style="color:red">Get list of Sub-Directories</span>

> Keyword : flyTdr

> Command : \x21\x00\x00\x00\x00-flyTdr=C:\\Users\\vboxuser\\Desktop

<img src="/assets/img/assignment/subdir.jpg">

<span style="color:lightgreen">exprfvlder</span> concatenates all the subdirectories to send back to the server.


### <span style="color:red">host Info</span>

> Keyword : inyTfo

> Command : \x07\x00\x00\x00\x00-inyTfo

<img src="/assets/img/assignment/userinfo.jpg">

<span style="color:lightgreen">accouQinfos</span> return the computer name, username and the malware's directory.

# <span style="color:red">Conclusion</span>

Most of the functionalities of this malware match those of <span style="color:red">Crimson RAT</span>. We can observe the similarities in the following blog.

- https://community.fortinet.com/t5/FortiEDR/Threat-Coverage-How-FortiEDR-protects-against-CrimsonRAT/ta-p/215398

## <span style="color:red">MITRE ATT&CK Tactic and Technique</span>

| ATT&CK Tactic          |      ATT&CK Techniqe                 |
| ---------------------- | ----------------------------         |
| COLLECTION             | Screen Capture T1113                 |         
| DISCOVERY              | Account Discovery T1087              |         
|                        | File and Directory Discovery T1083   |         
|                        | Process Discovery T1057              |         
|                        | Query Registry T1012                 |         
|                        | Software Discovery T1518             |         
|                        | System Information Discovery T1082   |         
|                        | System Owner/User Discovery T1033    |
| PERSISTENCE            | Registry Run Keys T1547              |
| COMMAND AND CONTROL    | Non-Standard Port T1571              |

## <span style="color:red">network indicators</span>
- 162.245.191.217
- 210.115.211.107
- ports : [9149, 15198, 17818, 27781, 29224]

