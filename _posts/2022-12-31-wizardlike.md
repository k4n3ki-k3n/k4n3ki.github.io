---
title : Wizardlike
author : k4n3ki
date : 2022-12-31 23:00:00
categories : [writeup, Rev]
tags : [PicoCTF 2021, IDA]
---

# Wizardlike
Author : LT 'SYREAL' JONES

CTF : PicoCTF

## Description
```
Do you seek your destiny in these deplorable dungeons? If so, you may want to look elsewhere. Many have gone before you and honestly, they've cleared out the place of all monsters, ne'erdowells, bandits and every other sort of evil foe. The dungeons themselves have seen better days too. There's a lot of missing floors and key passages blocked off. You'd have to be a real wizard to make any progress in this sorry excuse for a dungeon!
'w', 'a', 's', 'd' moves your character and 'Q' quits. You'll need to improvise some wizardly abilities to find the flag in this dungeon crawl. '.' is floor, '#' are walls, '<' are stairs up to previous level, and '>' are stairs down to next level.
```
You can Download the Binary from [here](https://artifacts.picoctf.net/c/150/game).

Patched [Binary](/assets/files/20230101/wizardLike/game)

### Hint 1
Different tools are better at different things. Ghidra is awesome at static analysis, but radare2 is amazing at debugging.
### Hint 2
With the right focus and preparation, you can teleport to anywhere on the map.

## Solution

First when we run the binary in terminal, we can easily clear 3 levels, but there is no way to clear the 4th level.

To analyse the binary load it into IDA.

As its a stripped binary, we aren't able to see the function names or debugging information.

![file](/assets/img/20230101/wizardLike/mainfunctionPointer.jpg)

Here 
<span style="color: lightgreen;"> *sub_423540* </span>
is the 
<span style="color: lightgreen;"> *__libc_start_main* </span> 
function whose first argument 
<span style="color: lightgreen;"> *sub_402467* </span> 
must be 
<span style="color: lightgreen;"> *main* </span> 
function.

In main function, there are switch statements for setting up different level, after some deepshit, i saw a switch statement, for cases of 'a', 'w', 's', 'd'.

![keyCmp](/assets/img/20230101/wizardLike/keyCmp.jpg)

It's comparing the user keys for movements and calls the function accordingly but at starting of every function it calls a function <span style="color: lightgreen;"> *sub_4021B8* </span> that checks whether user is trying to cross the <span style="color: lightgreen;"> *'#'* </span> and <span style="color: lightgreen;"> *' '* </span> or not and will accordingly return 0 or 1. 

![unpatchedAsm](/assets/img/20230101/wizardLike/unpatchedAsm.jpg)

> **Trick** : What if we patch the function in a way, so that it always return 1. We will be able to move freely in the map, whether its '#' or spaces.

To patch the binary, **Go to Edit -> patch program -> assemble**. 
> **warning** : first click on the instruction you want to edit and then proceed.

![patchProgram](/assets/img/20230101/wizardLike/patchProgram.jpg)

As you can see in the picture above, its moving 0 in eax, just change it to 1, and the other instruction too.

![patchedAsm](/assets/img/20230101/wizardLike/patchedAsm.jpg)

You can see, in the pseudocode, that the function return 1 in every case.
To save the changes, **Go to Edit -> patch program -> Apply patches to input file**.

Voila!, the binary is patched, Now just run it, and find the flag by clearing the levels.

Here is the first part of flag:
![level 1](/assets/img/20230101/wizardLike/levels/level1.jpg)

You can find the rest of the level images in the [images](/assets/img/20230101/wizardLike/levels/) folder.

> The flag is : **picoCTF{ur_4_w1z4rd_8F4B04AE}**