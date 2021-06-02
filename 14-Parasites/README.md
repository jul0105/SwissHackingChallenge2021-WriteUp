# Cyber Space Adventure: Part 2 - Parasite

> Author : jul0105
> Date : 15.04.2021



## Challenge info

**Release** : Bundle 4 (10.04)

**Difficulty** : Hard

**Goal** : Advanced Reverse-Engineering.




## Analysis

1. Using Ghidra to decompile the binary, we see in the main function that the binary require an argument. This argument as to be equal to the next value :

```c
local_38 = 0x535f52337055732d;
local_30 = 0x6572433333333333;
local_28 = 0x4b436f6c4e755f74;
local_20 = 0xa676e697254735f;
local_18 = 0;
```

This represent the following string :

```
-sUp3R_S33333Cret_uNloCK_sTring
```

2. Then, the function `Child` is called and we enter the 6 level authentication protocol.
3. For each level :
   1. The user input a number
   2. This number is passed as an argument to the function `Dispatch`
   3. This function return another value
   4. This  value must be equal to a constant that is different for each level
4. This seems trivial, we only need to know what is done on the `Dispatch` function to be able to input the correct values.
5. The problem is, the `Dispatch` function only contains the instruction `UD2` which indicate an **Undefined Instruction**. So there is nothing to analyses statically.
6. I try to use gdb to read the return value of the `Dispatch` function but it fail because the `UD2` instruction make the program crash. This is strange because without the debugger, the program doesn't crash.



## Binary patch

1. So here I am, I cannot analyses the binary statically nor dynamically and I don't really know what is this instruction and how it behave.

2. I decide to try the nasty way: I patch the binary to get the value I want (return value of the `Dispatch` function)
3. I will write a `printf("%i", return_value);` after the call to `Dispatch`.
   1. `printf()` is `call 0x400770`
   2. `"%i"` is already stored at `0x4014e0`
   3. Return value of Dispatch is stored on register `rax`
4. So I use radare2 to write these instruction directly after `call Dispatch` :

```assembly
mov rdi, 0x4014e0	; "%i"
mov rsi, rax		; Dispatch return's value
mov eax, 0
call 0x400770 		; printf
call 0x400800 		; exit
```

5. Then I execute the binary and try some numbers. I realize that the `Dispatch` function return the **input XOR 1337133713**



## Getting the flag

1. As state before, each level have a constant value (**const**).
2. To validate the level, this has to be true : **const == input XOR 1337133713**
3. Since the const is known, we can calculate the input like this : **input = const XOR 1337133713**

```
LVLN: input = const XOR 133713371337

LVL1: 68738365 = 0x4babd7ac XOR 133713371337
LVL2: 66766995 = 0x4c49c202 XOR 133713371337
LVL3: 84726995 = 0x4abfde42 XOR 133713371337
LVL4: 78657879 = 0x4b0333c6 XOR 133713371337
LVL5: 77738469 = 0x4b113b74 XOR 133713371337
LVL6: 83954936 = 0x4ab20669 XOR 133713371337
```

4. Since we have all the necessary input, we can get the flag :

```bash
printf "%i\n%i\n%i\n%i\n%i\n%i\n" 68738365 66766995 84726995 78657879 77738469 83954936 | ./parasites_fixed -sUp3R_S33333Cret_uNloCK_sTring
```

Flag :

```
shc2021{DISABLE_THE_NANOMITES_1$}
```



PS: I was able to get the flag but I don't think this was the intended solution.

PS2: I'll be reading about nanomites.