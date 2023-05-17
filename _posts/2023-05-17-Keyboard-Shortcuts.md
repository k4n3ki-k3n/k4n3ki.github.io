---
title: Essential Keyboard Shortcuts
author: k4n3ki
date: 2023-05-17 2:4:00 -500
categories: [Tools]
tags: [ollydbg, windbg]
---

Useful keyboard shortcuts for Tools related to Reverse Engineering.

Tools covered :
- OllyDbg
- IDA Pro
- Immunity Debugger
- WinDbg

## <span style = "color:red;">OllyDbg</span>

| Shortcut | Function |
| -------- | -------- |
| <span style="color:lightgreen;"> **Global shortcuts** </span> | 
| Ctrl+F2 |	Restart program
| Alt+F2 |	Close program
| F3 |	Open new program
| F5 |	Maximize/restore active window
| Alt+F5 |	Make OllyDbg topmost
| F7 |	Step into (entering functions)
| Ctrl+F7 |	Animate into (entering functions)
| F8 |	Step over (executing function calls at once)
| Ctrl+F8 |	Animate over (executing function calls at once)
| F9 |	Run
| Shift+F9 |	Pass exception to standard handler and run
| Ctrl+F9 |	Execute till return
| Alt+F9 |	Execute till user code
| Ctrl+F11 |	Trace into
| F12 |	Pause
| Ctrl+F12 |	Trace over
| Alt+B |	Open Breakpoints window
| Alt+C |	Open CPU window
| Alt+E |	Open Modules window
| Alt+L |	Open Log window
| Alt+M |	Open Memory window
| Alt+O |	Open Options dialog
| Ctrl+T |	Set condition to pause Run trace
| Alt+X |	Close OllyDbg
| <span style="color:lightgreen;"> **Disassembler Shortcuts** </span> |
| F2 |	Toggle breakpoint
| Shift+F2 |	Set conditional breakpoint
| F4 |	Run to selection
| Alt+F7 |	Go to previous reference
| Alt+F8 |	Go to next reference
| Ctrl+A |	Analyse code
| Ctrl+B |	Start binary search
| Ctrl+C |	Copy selection to clipboard
| Ctrl+E |	Edit selection in binary format
| Ctrl+F |	Search for a command
| Ctrl+G |	Follow expression
| Ctrl+J |	Show list of jumps to selected line
| Ctrl+K |	View call tree
| Ctrl+L |	Repeat last search
| Ctrl+N |	Open list of labels (names)
| Ctrl+O |	Scan object files
| Ctrl+R |	Find references to selected command
| Ctrl+S |	Search for a sequence of commands
| Asterisk (*) |	Origin
| Enter |	Follow jump or call
| Plus (+) |	Go to next location/next run trace item
| Minus (-) |	Go to previous location/previous run trace item
| Space (  ) |	Assemble
| Colon (:) |	Add label
| Semicolon (;) |	Add comment


## <span style="color:red;">IDA Pro</span>
| Shortcut | Function |
| -------- | -------- |
| <span style="color:lightgreen;">**Navigation**</span>
| Enter | Jump to operand 
| G | Go to Address
| Ctrl+P | Jump to function
| Ctrl+E | Jump to entry point
| ESC | Jump to previous position
| Ctrl+L | Jump by name
| X | xref
| <span style="color:lightgreen;">**Search**</span>
| Alt+C | Next code
| Alt+I | Immediate value
| Alt+T | Text
| Alt+B | Sequence of bytes
| Ctrl+D | Next data
| Ctrl+I | Next immediatevalue
| Ctrl+T | Next text
| Ctrl+B | Next sequence of bytes
| <span style="color:lightgreen;">**Graphing**</span>
| F12 | Flow Chart
| Ctrl+F12 | Function calls
| <span style="color:lightgreen;">**Subviews**</span>
| Shift+F4 | Name
| Shift+F12 | Strings
| Shift+F3 | Functions
| Shift+F7 | Segments
| <span style="color:lightgreen;">**Debugger**</span>
| F9 | Start
| F7 | Step into
| Ctrl+F7 | Run until return
| Ctrl+F2 | Stop process
| F8 | Step over
| Ctrl+Alt+B | List Breakpoints
| <span style="color:lightgreen;">**Other**</span>
| C | Code
| U | Undefine
| Shift+; | Enter comment
| P | Create function
| E | Set function end
| M | Member enumeration
| D | Data
| N | Rename
| ; | Enter repeatable comment
| Alt+P | Edit function
| Y | Declare function type
| Shift+F2 | Run script

## <span style="color:red;">Immunity Debugger</span>
| Shortcut | Function |
| -------- | -------- |
| F9 | Run
| F2 | Set brekpoint
| F8 | Step over
| F7 | Step into
| F12 | Pause
| Ctrl+F9 | Execute till return
| Alt+B | Open breakpoint Window
| Alt+E | Open module window
| Alt+M | Open memory window
| Alt+C | Open CPU window
| Alt+L | Open log window
| ALt+O | Open option window

## <span style="color:red;">WinDbg</span>
| Shortcut | Function |
| -------- | -------- |
| <span style="color:lightgreen;">**Flow Control**</span>
| F5 |	Continue
| F10 |	Step over
| F11 |	Step Into
| Shift+F11 |	Step out
| F7 |	Run to line
| Ctrl+Shift+I |	Set instruction pointer to highlighted line
| Ctrl+Break or Alt+Del |	Break
| Ctrl+Shift+F5 |	Restart
| Shift+F5 |	Stop debugging
| Alt+H,D |	Detach
| <span style="color:lightgreen;">**Setup**</span>
| F6 |	Attach to process
| Ctrl+R |	Connect to remote
| Ctrl+D |	Open dump file
| Ctrl+K |	Attach to kernel debugger
| Ctrl+E |	Launch process
| Ctrl+P |	Launch app package
| <span style="color:lightgreen;">**Breakpoints**</span>
| F9 |	Toggle breakpoint on highlighted line
| Ctrl+Alt+K |	Toggle initial break
| Alt+B,A |	Add breakpoint
| <span style="color:lightgreen;">**Windowing**</span>
| Ctrl+Tab |	Open window changer
| Ctrl+1 |	Open/focus on command window
| Ctrl+2 |	Open/focus on watch window
| Ctrl+3 |	Open/focus on locals window
| Ctrl+4 |	Open/focus on registers window
| Ctrl+5 |	Open/focus on memory window
| Ctrl+6 |	Open/focus on stack window
| Ctrl+7 |	Open/focus on disassembly window
| Ctrl+8 |	Open/focus on breakpoints window
| Ctrl+9 |	Open/focus on thread window
| <span style="color:lightgreen;">**Scripting**</span>
| Ctrl+Shift+O |	Open script
| Ctrl+Shift+Enter |	Execute script
| Ctrl+S |	Save script
| Alt+S,N |	New script
| Alt+S,U |	Unlink script