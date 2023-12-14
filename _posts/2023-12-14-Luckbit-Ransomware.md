---
title : Luckbit Ransomware
author : k4n3ki
date : 2023-12-14 1:00:00 -500
categories: [Malware Analysis]
tags: [Ransomware, Reverse Engineering, .Net]
---

# <span style="color:red">Overview</span>

<span style="color:lightgreen">Malware</span> is like a sneaky computer bug that can make your device sick. It's a type of software that can cause problems by doing things you didn't ask it to, like stealing your information or making your computer act strangely. Just like how you catch a cold, your computer can catch malware from unsafe websites or email attachments. It's important to be careful and use antivirus tools to keep your device healthy.

<span style="color:lightgreen">Ransomware</span> is a kind of computer troublemaker that takes your files hostage. Imagine if your favorite toy was locked away, and you had to pay to get it back. That's what ransomware does to your computer files-it locks them up, and the bad guys ask for <span style="color:lightgreen">money</span> to set them free. It's like a digital kidnapper. To stay safe, avoid clicking on strange links or downloading things from unknown sources.

<img src="/assets/img/luckbit/tempWallpaper.jpg">

## <span style="color:red">Content</span>
- [overview](#overview)
- [IOCs](#iocs)
- [Static Analysis](#static-analysis)
    - [Virustotal Report](#virustotal-report)
    - [Capa](#capa)
    - [DnSpy](#dnspy)
- [Dynamic Analysis](#basic-dynamic-analysis)
    - [Basic Dynamic Analysis](#basic-dynamic-analysis)
    - [Advanced Dynamic Analysis](#advanced-dynamic-analysis)
        - [File Encryption](#file-encryption)
        - [Change Wallpaper](#create-wallpaper-image)
        - [Refresh Display settings](#refresh-display-settings)
        - [Create Ransom Note](#create-readme-file)
        - [Delete Shadow Files](#delete-shadow-files)
        - [Powershell to remove Traces](#powershell-to-remove-traces)
- [MITRE ATT&CK Tactic and Technique](#mitre-attck-tactic-and-technique)
- [Conclusion](#conclusion)


# <span style="color:red">IOCs</span>

- **MD5** : 4d05d4b28f54a4f407f50a4fa3297c3f
- **SHA256** : 206e71939ac01a149d2fcec629758524a2597bd7d07e6bb3fb01d0f4e28f5b8e
- **Malware Sample** : https://bazaar.abuse.ch/sample/206e71939ac01a149d2fcec629758524a2597bd7d07e6bb3fb01d0f4e28f5b8e/


# <span style="color:red">Static Analysis</span>

Loading the binary into Detect-it-Easy reveals that it is a PE32 <span style="color:lightgreen">.NET</span> binary protected by the <span style="color:lightgreen">Obfuscar</span> obfuscator. The reported creation year of the exe is 2041. It contains only one import, [_CorExeMain](https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/corexemain-function), which initializes the Common Language Runtime (CLR).

<img src="/assets/img/luckbit/die.jpg">

The <span style="color:lightgreen">entropy</span> of the .text section is 7.627, indicating that it is packed. It also contains two resources: <span style="color:lightgreen">Version Info</span> and <span style="color:lightgreen">Manifest</span>.

<img src="/assets/img/luckbit/entropy.jpg">

## <span style="color:red">Virustotal Report</span>

When searched on [VirusTotal](https://www.virustotal.com/gui/file/206e71939ac01a149d2fcec629758524a2597bd7d07e6bb3fb01d0f4e28f5b8e/detection), the hash was flagged as malicious by 55 out of 72 vendors. The detection revealed several IPs, and the malware drops multiple files on the system.

<img src="/assets/img/luckbit/virustotal.jpg">

## <span style="color:red">Capa</span>


Capa detects numerous capabilities of this malware, such as <span style="color:lightgreen">host interaction</span>, <span style="color:lightgreen">data manipulation</span> using <span style="color:lightgreen">Base64</span>, <span style="color:lightgreen">RSA</span>, <span style="color:lightgreen">SHA256</span>, etc.

<img src="/assets/img/luckbit/capa.jpg">


# <span style="color:red">DnSpy</span>

For further analysis, let's load the binary into <span style="color:lightgreen">**DnSpy**</span> to decompile the code. It contains five internal classes named a, A, b, B, and BF435CFA-E253-40F2-84CD-A545B5F84149.

## <span style="color:red">Class BF435CFA-E253-40F2-84CD-A545B5F84149</span>

The class BF435CFA-E253-40F2-84CD-A545B5F84149 contains a constructor that updates a large chunk of bytes using XOR.

<img src="/assets/img/luckbit/xor.jpg">

To observe what it XORs, I wrote a Python script to check.

```python
import pefile

pe = pefile.PE("206e71939ac01a149d2fcec629758524a2597bd7d07e6bb3fb01d0f4e28f5b8e.exe")

offset = 0x1dc4
size = 0x7e1c

def read_bytes():
    try:
        pe_file_offset = pe.get_offset_from_rva(offset)
        data = pe.get_data(pe_file_offset, size)
        pe.close()
        return data
    except pefile.PEFormatError as e:
        print(f"[-] Error reading PE file: {e}")
        return None

def xor_decrypt(bytes):
    f = ""
    for i in range(len(bytes)):
        f += chr(bytes[i] ^ i ^ 170)
    return f

enc_byte_chunk = read_bytes()
base_enc_strings = xor_decrypt(enc_byte_chunk)

print(base_enc_strings)
```

The output contains <span style="color:lightgreen">base64-encoded</span> strings and the command "<span style="color:lightgreen">rundll32.exe user32.dll,UpdatePerUserSystemParameters 1, True</span>" which is often used to force Windows to refresh its display settings or apply changes to the user interface.

<img src="/assets/img/luckbit/pyxor.jpg">


These strings are retrieved in chunks whenever needed by calling specific functions.

<img src="/assets/img/luckbit/chunks.jpg">

To understand how it fetches the strings and continues the flow, let's examine the reference for the above command. It retrieves the command in two parts: first, "rundll32.exe," which is of length 12, and then the remaining part, "user32.dll,UpdatePerUserSystemParameters 1, True," which is of length 48.

<img src="/assets/img/luckbit/fetch.jpg">

These strings are passed to function as arguments where it starts a new process and sets the first string as executable to run and second string as its arguments. The WindowStyle of this process is set to <span style="color:lightgreen">ProcessWindowStyle.hidden</span> to hide the window.

<img src="/assets/img/luckbit/stringprocess.jpg">

## <span style="color:red">[De4dot](https://github.com/de4dot/de4dot)</span>

To decrypt the string, use the <span style="color:red">De4dot</span> tool, which is a .NET deobfuscator and unpacker. Use the following command for string decryption:

> de4dot.exe 206e71939ac01a149d2fcec629758524a2597bd7d07e6bb3fb01d0f4e28f5b8e.exe --strtyp emulate --strtok "7FFC0B98-1A44-4DFA-9214-E12B36C3AD43.BF435CFA-E253-40F2-84CD-A545B5F84149::" --strtok 0x06000024 --strtok 0x06000011 -o test1.exe

<img src="/assets/img/luckbit/de4dot.jpg">

## <span style="color:red">Class a</span>

The main functionality of class a is to read a file and write its content to another file in an encrypted form.

<img src="/assets/img/luckbit/a.jpg">

## <span style="color:red">Class A</span>

This contains the main functionalities of the ransomware, which traverse through the directories, get the files and all.

<img src="/assets/img/luckbit/AA.jpg">

## <span style="color:red">Class b</span>

This class defines a class that inherits from <span style="color:lightgreen">ApplicationSettingsBase</span> and is used for managing application settings features.

<img src="/assets/img/luckbit/b.jpg">

## <span style="color:red">Class B</span>

This class contains static properties for accessing <span style="color:lightgreen">ResourceManager</span> and <span style="color:lightgreen">CultureInfo</span>. It likely plays a role in managing resources (e.g., strings, images) for the sample and ensures that these resources are easily accessible and modifiable.


# <span style="color:red">Basic Dynamic Analysis</span>

Static Analysis in DnSpy doesn't provide much insight since strings are decrypted. Let's attempt to run it in a protected environment to observe the execution flow. Initiate <span style="color:lightgreen">**Procmon**</span> and include a process name filter to specifically capture the logs generated by the sample.

The malware first traverses all directories, encrypting files with extensions such as .jpg, .txt. Additionally, it appends a new extension "<span style="color:lightgreen">.znhpj</span>" to the filenames.

<img src="/assets/img/luckbit/pencrypt.jpg">

After encrypting the files, the malware creates a <!-- [<span style="color:red"><ins>README_K.log</ins></span>](/assets/img/luckbit/README_K.log) --> README_K.log file in each directory. This file contains the ransom note detailing the attack and includes instructions on how to pay the ransom. It modifies the wallpaper by replacing it with an image containing a message about Luckbit along with information from the README_K.log file.

```log
Urgent Notice - Your Data Has Been Encrypted

Attention,

We regret to inform you that your computer network has been compromised, and all your valuable data has been encrypted using advanced encryption algorithms. Our team of skilled hackers gained access to your systems through a vulnerability we discovered, granting us full control over your files and databases.

We are writing to you as the sole entity capable of reversing this encryption and restoring your data to its original state. However, we must stress that time is of the essence. In order to initiate the data decryption process, we require a payment of MYR 20 million in BTC equivalent within 7 days. Failure to comply with our demands will result in permanent data loss, as we will securely destroy the decryption key and releasing all your files for public access.

Please understand that we are professionals, and we have taken steps to ensure the anonymity of both parties involved. Attempts to involve law enforcement or other cybersecurity firms will be met with severe consequences, including the public release of your sensitive data. We are aware of the repercussions you may face if certain confidential information falls into the wrong hands.

To proceed with the payment and restore your data, please follow the instructions below:

- Acquire MYR 20 million of BTC equivalent through a reputable cryptocurrency exchange.
- Send the Bitcoin to the following address: 1LUDkWuaxQnsRyj4VUvAkbYTDodvGo7RjS
- Once the payment is confirmed, send an email to znhsupport@protonmail[.]com with the subject line: 'Payment Confirmation' and include the Bitcoin transaction ID.
- Upon receiving your confirmation, we will provide you with the decryption tool and further instructions to restore your data.
- Please present the following unique ID when contacting us: 0f9962d3ed0f0f5f00dbf61820ff95a593ef49a53625d355f95fcc21584e8808
- Access the following URL via TOR network: http[:]//luckbit53sdne5yd5vdekadhwnbzjyqlbjkc4g33hs6faphfkvivaeid[.]onion/

We understand the inconvenience and distress this situation may cause you, but we assure you that cooperating with us is your best option for a swift resolution. Remember, time is limited, and any attempts to tamper with or investigate the situation will lead to irreversible consequences.

Do not underestimate the gravity of this situation. We have targeted your organization for a reason, and we possess the capability to carry out our threats. Your cooperation is essential if you want to regain control over your valuable data.

Sincerely,
ZNH
```

<img src="/assets/img/luckbit/preadme.jpg">

Observing the process activity, it initiates a process with <span style="color:lightgreen">powershell.exe</span> and executes a script in file <!-- [<span style="color:red"><ins>tmpF593.tmp.ps1</ins></span>](/assets/img/luckbit/tmp.ps1) --> tmpF593.tmp.ps1.

```powershell

$soNJkXUO = Get-Process 3K0JfF4BjXG6mMisOnUXL2mGOOBeDHM7vZK4ILhZbtc -ErrorAction SilentlyContinue
while ($soNJkXUO) {
  if (!$soNJkXUO.HasExited) {
	    write-host 'DtwpkcPr';
  } else {
      if (Test-Path -Path 'C:\ProgramData\Windows\System32\3K0JfF4BjXG6mMisOnUXL2mGOOBeDHM7vZK4ILhZbtc.exe') {
        Add-Type -AssemblyName Microsoft.VisualBasic;
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile('C:\ProgramData\Windows\System32\3K0JfF4BjXG6mMisOnUXL2mGOOBeDHM7vZK4ILhZbtc.exe','OnlyErrorDialogs','SendToRecycleBin');
        Remove-Item $script:MyInvocation.MyCommand.Path -Force
        break
      } else {
        Remove-Item $script:MyInvocation.MyCommand.Path -Force
        break
      }
  }
}
Remove-Item $script:MyInvocation.MyCommand.Path -Force
Remove -Variable soNJkXUO
```

<img src="/assets/img/luckbit/ps.jpg">

This script checks for a process named "3K0JfF4BjXG6mMisOnUXL2mGOOBeDHM7vZK4ILhZbtc", if this process is running, it prints "DtwpkcPr". If the process has exited, it checks if a file exists at a specific path (<span style="color:lightgreen">C:\ProgramData\Windows\System32\3K0JfF4BjXG6mMisOnUXL2mGOOBeDHM7vZK4ILhZbtc.exe</span>). If the file exists, it uses Microsoft.VisualBasic to delete the file to the recycle bin and then removes the script file itself. If the file does not exist, it simply removes the script file.

# <span style="color:red">Advanced Dynamic Analysis</span>

By employing advanced dynamic analysis and debugging, we can analyze the sample step by step, allowing us to inspect the strings and arguments passed to the functions.

The entry point of this sample is method A in class A. In this method, an array of folders is created by deobfuscating strings. 

<img src="/assets/img/luckbit/folders.jpg">

## <span style="color:red">File Encryption</span>

The deobfuscation process involves using Base64 and AES algorithms to decrypt the strings in method A.A.C.

<img src="/assets/img/luckbit/aes.jpg">

The sample employs the same key and IV (Initialization Vector) for decrypting all the strings.

<img src="/assets/img/luckbit/chef.jpg">

After obtaining the folder list, it iteratively passes each folder name to the A.A.a method through a for loop. Within this method, it retrieves a list of file extensions, which includes [".txt", ".pdf", ".jpg", ".doc", ".docx", ".ppt", ".xls", ".png", ".sql", ".sqlite", ".csv"].

<img src="/assets/img/luckbit/ext.jpg">

Then it gets the list of all the files present in the directory with one of the extensions from the above list. Afterward, it passes the file name and two other arguments to the method named A.A.B and deletes the file. Following that, it retrieves the list of sub-directories and passes them to the same method A.A.a recursively. It also checks for the strings "Startup" and "Temp" in the file and folder names.

The A.A.a method contains the implementation of RSA encryption. It takes three arguments: the RSA public key in XML format, the original filename, and the new filename with a '.znhpj' extension. It encrypts the file content using RSA and creates a new file.

<img src="/assets/img/luckbit/rsa.jpg">

## <span style="color:red">Create Wallpaper Image</span>

After encrypting all the files in "NFS," "Documents," "Desktop," "OneDrive," "GDRIVE," and "Google Drive," it calls A.A.c in which it retrieves an image by decrypting a chunk using base64 and saves the 'Wallpaper.jpg' in the Temp directory. After that, it passes the full path of that image to the A.A.B method.

<img src="/assets/img/luckbit/wallpaper.jpg">

A.A.B sets this image as the wallpaper by modifying the registries.

> HKEY_CURRENT_USER\ControlPanel\Desktop

| Value Name     |      Value Dat                 |
| ---------------------- | ----------------------------  |
| WallpaperStyle | 2 |
| TileWallpaper | 0 |
| Wallpaper | C:\Users\vboxuser\AppData\Local\Temp\tempWallpaper.jpg

<img src="/assets/img/luckbit/reg.jpg">

## <span style="color:red">Refresh Display Settings</span>

Next, A.A.B is called with two strings as arguments: "rundll32.exe" and "USER32.DLL,UpdatePerUserSystemParameters 1, True." This function starts a new process to execute rundll32.exe with the second string as its argument, forcing Windows to refresh its display settings or apply changes to the user interface.

<img src="/assets/img/luckbit/runas.jpg">

## <span style="color:red">Create README file</span>

Next, in a new thread, it starts creating the README_K.log file in "Users" and "NFS" directory.

While decrypting the content of the readme file, it creates a unique ID for every victim. This ID is the SHA256 hash of the Environment Username and a constant.

<img src="/assets/img/luckbit/readme.jpg">

Then, it calls another method to create the README_K.log file in all the subdirectories.

<img src="/assets/img/luckbit/subdir.jpg">

## <span style="color:red">Delete Shadow Files</span>

Next it runs a command "vssadmin delete shadows /for=c: /all" that uses the VSSAdmin (Volume Shadow Copy Service Administration) tool to delete shadow copies on the C: drive.

> Shadow Copy is a technology included in Microsoft Windows that can create backup copies or snapshots of computer files or volumes, even when they are in use. It is implemented as a Windows service called the Volume Shadow Copy service.

<img src="/assets/img/luckbit/vss.jpg">

## <span style="color:red">Powershell to remove Traces</span>

Next, it creates a PowerShell script, saves it to the "C:\Users\vboxuser\AppData\Local\Temp" directory, and executes it using powershell.exe in a new process. This script checks for a process named "3K0JfF4BjXG6mMisOnUXL2mGOOBeDHM7vZK4ILhZbtc", if this process is running, it prints "DtwpkcPr". If the process has exited, it checks if a file exists at a specific path (C:\ProgramData\Windows\System32\3K0JfF4BjXG6mMisOnUXL2mGOOBeDHM7vZK4ILhZbtc.exe). If the file exists, it uses Microsoft.VisualBasic to delete the file to the recycle bin and then removes the script file itself. If the file does not exist, it simply removes the script file.

<img src="/assets/img/luckbit/script.jpg">




# <span style="color:red">MITRE ATT&CK Tactic and Technique</span>

| ATT&CK Tactic          |      ATT&CK Techniqe                 |
| ---------------------- | ----------------------------         |
| Defense Evasion        | Deobfuscate/Decode Files or Information T1140 |
|                        | Obfuscated Files or Information T1027   |
| DISCOVERY              | Account Discovery T1087                 |
|                        | File and Directory Discovery T1083      |
|                        | Query Registry T1012                    |
|                        | System Owner/User Discovery T1033       |

# <span style="color:red">Conclusion</span>

This sample is a ransomware named Luckbit, which encrypts files using the RSA encryption algorithm. It creates files with a unique extension ".znhpj" and deletes the original files. Additionally, it creates a wallpaper image in the Temp directory and changes the wallpaper by manipulating registries. It then refreshes the display settings by running a command in PowerShell. Following that, it creates README_K.log files in all of the subdirectories. Finally, it executes a PowerShell script to delete the sample and the script itself.
