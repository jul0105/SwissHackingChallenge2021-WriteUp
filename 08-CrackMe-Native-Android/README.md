# CrackMe Native - Android

> Author : jul0105
> Date : 13.03.2021



## Challenge info

**Release** : Bundle 2 (13.03)

**Difficulty** : Medium

**Goal** : The password is somewhere hidden in this app. Extract it. The password is the flag. The app is armored with "Anti-Hooking" protection.



## Solve

1. Firstly, decompile java code from the apk with `jadx` :

```
jadx 65cd923-4a36-4ae6-ba82-a936c6f76514.apk
```

2. In the generated directory, the code of the application is in the directory `sources/org/bfe/crackmenative`
3. The class `ui/LoginViewModel.java` seems to be the point where the password is checked. Starting with the function `login(String str)` :

```java
public void login(String str) {
    if (checkHooking()) {
        this.loginResult.setValue(new LoginResult(Integer.valueOf((int) R.string.must_not_hook)));
        return;
    }
    try {
        int[] checkPw = checkPw(getCode(str));
        if (checkPw.length > 0) {
            this.loginResult.setValue(new LoginResult(new LoggedInUser(getStringFromCode(checkPw), "Well done you did it.")));
            return;
        }
        this.loginResult.setValue(new LoginResult(Integer.valueOf((int) R.string.login_failed)));
    } catch (Exception unused) {
        this.loginResult.setValue(new LoginResult(Integer.valueOf((int) R.string.error_logging_in)));
    }
}
```

4. The most interesting line on the above code is `int[] checkPw = checkPw(getCode(str));`
   - `str` is probably the password
   - `getCode()` convert a string to an array of int **while XORing it with a given array of int**
   - `checkPw()` is a function that is not present in the source code
5. The `getCode()` function XOR the password with this array of int **called x0** :

```java
protected static int[] x0 = {121, 134, 239, 213, 16, 28, 184, 101, 150, 60, 170, 49, 159, 189, 241, 146, 141, 22, 205, 223, 218, 210, 99, 219, 34, 84, 156, 237, 26, 94, 178, 230, 27, 180, 72, 32, 102, 192, 178, 234, 228, 38, 37, 142, 242, 142, 133, 159, 142, 33};
```

6. Only the function signature of `checkPw()` appear in the code. But the next lines indicates that a library is loaded.

```java
public native int[] checkPw(int[] iArr);

static {
	System.loadLibrary("native-lib");
}
```

7. The file `resources/lib/x86/libnative-lib.so` is the library loaded
8. Using Ghidra, we can find a function called `Java_org_bfe_crackmenative_ui_LoginViewModel_checkPw`
9. This function seems to first check if frida or Xposed is launched and if this is not the case, it check the password
10. Here is the actual password check :

```c
input = (**(code **)(*(int *)param_1[0] + 0x2ec))(param_1[0],param_1[2],0);
x5 = &DAT_00010b80;
x7 = (uint *)&DAT_00010b4c;
x9 = &DAT_000109e4;
count = -0x6c;
do {
    iVar4 = iVar2;
    if ((*x9 ^ *(uint *)(input + 0x6c + count) ^ *x7) != *x5) break;
    x5 = x5 + 1;
    x7 = x7 + -1;
    x9 = x9 + 1;
    count = count + 4;
    iVar4 = param_1[2];
} while (count != 0);
```

11. The above code retrieve 3 array of int (x5, x7 and x9) and then check for each value of the input that `x9 XOR input XOR x7 == x5`. While this condition is true, the check continue (max 27 values).
    1. x5, x7 and x9 are known constant values
    2. input is `password XOR x0` (x0 is the array of int given in point [5])
12. So if `x9 XOR password XOR x0 XOR x7 == x5` then **`password = x0 XOR x5 XOR x7 XOR x9`**

13. To calculate the password, I retrieve the values of x5, x7 and x9 from Ghidra (For x7, since the iterator is decreasing, I take the 27 values upward instead of downward). Then, calculate the password :

```python
x0 = [121, 134, 239, 213, 16, 28, 184, 101, 150, 60, 170, 49, 159, 189, 241, 146, 141, 22, 205, 223, 218, 210, 99, 219, 34, 84, 156, 237, 26, 94, 178, 230, 27, 180, 72, 32, 102, 192, 178, 234, 228, 38, 37, 142, 242, 142, 133, 159, 142, 33]

x5 = b'\x80\xe3\xda\xc7\x2e\xf1\xa2\x91\x6b\xdc\x6b\xb5\xe5\xaf\x3f\xb9\xee\x5b\x26\x92\x66\xc5\xcb\xde\x81\x79\xda'
x7 = b'\x4c\x7b\x73\x6f\x72\x72\x79\x2e\x74\x68\x69\x73\x2e\x69\x73\x2e\x4e\x4f\x54\x2e\x74\x68\x65\x2e\x66\x6c\x61'
x9 = b'\xd0\x45\x28\x76\x6f\xf3\x5a\xf4\xc7\xce\xfb\xc3\x7f\x48\xce\x3c\x3a\x0b\xf1\x53\xb1\x4b\xb9\x5e\xa2\x65\x77'

for i in range(27):
    result = int(x0[i]) ^ x5[i] ^ x9[i] ^ x7[len(x7) - 1 - i]
    print(chr(result), end='')
print()
```

14. The password is the flag :

```
HL{J4v4.nativ3.d0.n0t.c4r3}
```

