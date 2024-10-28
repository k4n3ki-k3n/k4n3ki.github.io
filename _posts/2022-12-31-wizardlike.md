---
title : Wizardlike
author : k4n3ki
date : 2022-12-31 23:00:00
categories : [writeup, Rev]
tags : [PicoCTF 2021, IDA]
---

# <span style = "color:red;">Content</span>
- [Challenge Description](#challenge-description)
- [Solution](#solution)

# <span style = "color:red;">Challenge Description</span>

Challenge Name : Wizardlike

Author : LT 'SYREAL' JONES

CTF : PicoCTF
```
Do you seek your destiny in these deplorable dungeons? If so, you may want to look elsewhere. Many have gone before you and honestly, they've cleared out the place of all monsters, ne'erdowells, bandits and every other sort of evil foe. The dungeons themselves have seen better days too. There's a lot of missing floors and key passages blocked off. You'd have to be a real wizard to make any progress in this sorry excuse for a dungeon!
'w', 'a', 's', 'd' moves your character and 'Q' quits. You'll need to improvise some wizardly abilities to find the flag in this dungeon crawl. '.' is floor, '#' are walls, '<' are stairs up to previous level, and '>' are stairs down to next level.
```
The challenge binary can be downloaded from the [link](https://artifacts.picoctf.net/c/150/game), and the patched binary is available [here](/assets/files/20230101/wizardLike/game).

> Hint 1 : Different tools are better at different things. Ghidra is awesome at static analysis, but radare2 is amazing at debugging.

> Hint 2 : With the right focus and preparation, you can teleport to anywhere on the map.

# <span style = "color:red;">Solution</span>

When running the binary in the terminal, the first three levels are easily cleared, but the fourth level appears unsolvable. Loading the binary into IDA for analysis shows that, being stripped, it lacks function names and debugging information, making deeper analysis challenging.

![file](/assets/img/20230101/wizardLike/mainfunctionPointer.jpg)

Here, <span style="color: lightgreen;">sub_423540</span> is identified as the <span style="color: lightgreen;">__libc_start_main</span> function, with its first argument, <span style="color: lightgreen;">sub_402467</span>, likely being the <span style="color: lightgreen;">main</span> function. In the main function, there are switch statements setting up different levels. After some digging, I found a switch statement handling the cases for 'a', 'w', 's', and 'd'.

![keyCmp](/assets/img/20230101/wizardLike/keyCmp.jpg)

The program compares user movement keys and calls the corresponding function, but at the start of each, it calls <span style="color: lightgreen;"> *sub_4021B8* </span>, which checks if the user is attempting to cross <span style="color: lightgreen;"> *'#'* </span> or <span style="color: lightgreen;"> *"''"* </span> and returns 0 or 1 accordingly.

![unpatchedAsm](/assets/img/20230101/wizardLike/unpatchedAsm.jpg)

> **Trick** : Patching the function to always return 1 would allow unrestricted movement across the map, bypassing both '#' and empty spaces.

To patch the binary in IDA Pro, **navigate to Edit -> Patch Program -> Assemble**. 

> **warning** : First, click on the instruction to edit before proceeding.

![patchProgram](/assets/img/20230101/wizardLike/patchProgram.jpg)

As shown in the image above, it sets 0 in eax; simply change it to 1, along with the other instruction.

![patchedAsm](/assets/img/20230101/wizardLike/patchedAsm.jpg)

The pseudocode indicates that the function returns 1 in every case. To save the changes, **navigate to Edit → Patch Program → Apply Patches to Input File**.

The binary is now successfully patched. Simply run it and clear the levels to find the flag. Here is the first part of the flag:

![level 1](/assets/img/20230101/wizardLike/levels/level1.jpg)

The remaining level images can be found in the [images](https://github.com/0xk4n3ki/0xk4n3ki.github.io/tree/master/assets/img/20230101/wizardLike/levels) folder.

> The flag is : <span style = "color:lightgreen;">**picoCTF{ur_4_w1z4rd_8F4B04AE}**</span>
