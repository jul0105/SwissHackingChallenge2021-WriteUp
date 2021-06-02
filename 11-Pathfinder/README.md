# Cyber Space Adventure: Part 1 - Pathfinder

# BootMe

> Author : jul0105
> Date : 27.03.2021



## Challenge info

**Release** : Bundle 3 (27.03)

**Difficulty** : Easy

**Goal** : Reverse-Engineering of massive callgraphs.



## Solve

1. Firstly, I used Ghidra to decompile the binary file. 
2. I saw that the strings `You reached your destination.` and `You died.` has a lot of reference in a function. This function contains a lot of useless comparison and jumps.

3. Following the comparison and jumps, I found the following code

```c
if (strcmp(local_3c,(char *)&local_28)) {
    puts("You reached your destination.");
    puts("A massive abandoned spacestation appears in front of you");
}
else {
    puts("You died.");
}
```

This code compare two strings. If both strings are equals, we are done.



4. The first string is the password. 

```c
printf("Enter the password: ");
scanf("%8s",local_3c);
```

The password must be <= 8 chars.



5. The second string is a known string that is equal to `CYHSZZBU`.

```c
local_28 = 0x53485943; // "SHYC"
local_24 = 0x55425a5a; // "UBZZ"
```



6. Just after the password input, the password is modified in this loop :

```c
i = 0;
while (i < 8) {
    password[i] = FUN_08048569((int)password[i],i + 8);
    i = i + 1;
}
```

This code loop over the 8 char of the password an call the following function :

```c
int FUN_08048569(int current_char,int counter) {
  if ((0x40 < current_char) && (current_char < 0x5b)) {
    return (current_char + -0x41 + counter * 0x1f) % 0x1a + 0x41;
  }
  puts("You died.");
  exit(1);
}
```

This function do the following things :

- Ensure that all char in password is uppercase (ASCII 0x41 - 0x5b)
- Modify the current char and return it



7. So to summary, here is how the password is checked : 

   - `MODIFY(password) = "CYHSZZBU"` 

   - where `MODIFY` is the following operation on each char 

      `(current_char + -0x41 + counter * 0x1f) % 0x1a + 0x41;`.

      

8. Now that I have all the necessary info, I can get the password with the following python script :

```python
hardcoded = b'CYHSZZBU'

for i in range(len(hardcoded)):
    for j in range(0x41, 0x5b):
        if ((j - 0x41 + ((i + 8) * 0x1f)) % 0x1a) + 0x41 == hardcoded[i]:
            print(chr(j), end='')
print()
```

9. And here is the password :

```
OFJPRMJX
```

10. And the flag :

```
shc2021{OFJPRMJX}
```

