# CrackMe Simple - Android

> Author : jul0105
> Date : 02.03.2021



## Challenge info

**Release** : Bundle 1 (01.03)

**Difficulty** : Easy

**Goal** : The password is somewhere hidden in this app. Extract it. The password is the flag.



## Solve

1. Decompile java code from the apk with `jadx`

```
jadx 174bb954-15e1-4483-b4ec-7e5fae2e1eff.apk
```

2. In the generate directory, go to `sources/org/bfe/crackmesimple/`. This java package contains the code of the application.

3. In the class `ui/LoginViewModel.java`, we can see that during the login procedure, a byte array is decrypted and compared to the inputed password. If the two strings are equals, the user is granted access.
```java
private static byte[] exs = {-28, 73, 79, 78, 113, 73, 101, 98, 115, 6, 27, -35, 111, -55, -114, -11, -29, 0, -73, 91, 115, -24, -4, -94, -59, 43, -57, 112, 11, -54, -115, 2};

/* ... */

public void login(String str) {
    try {
        String str2 = new String(AESUtil.decrypt(exs));
        if (str.equals(str2)) {
            this.loginResult.setValue(new LoginResult(new LoggedInUser(str2, "Well done you did it.")));
            return;
        }
        this.loginResult.setValue(new LoginResult(Integer.valueOf((int) R.string.wrong_password)));
    } catch (Exception unused) {
        this.loginResult.setValue(new LoginResult(Integer.valueOf((int) R.string.error_logging_in)));
    }
}
```

4. In the class `data/LoggedInUser.java`, we realize that the first parameter of the constructor is in fact the flag.

5. So in summary, `exs` is the encrypted flag using `AESUtil` class.

6. In the class `util/AESUtil.java`, we see that the IV and the key are hard-coded.

```java
public class AESUtil {
    private static final String ENCRYPTION_IV = "SHCUOkfd89ut7777";
    private static final String ENCRYPTION_KEY = "Simpleji4todnkfL";

    public static byte[] encrypt(byte[] bArr) {/* ... */}

    public static byte[] decrypt(byte[] bArr) {/* ... */}

    static AlgorithmParameterSpec makeIv() {/* ... */}

    static Key makeKey() {/* ... */}
}
```

7. We can just extract the class AESUtil and add it a main function to decrypt the ciphertext :


```java
public static void main(String args[]) {        
    byte[] exs = {-28, 73, 79, 78, 113, 73, 101, 98, 115, 6, 27, -35, 111, -55, -114, -11, -29, 0, -73, 91, 115, -24, -4, -94, -59, 43, -57, 112, 11, -54, -115, 2};
    String str2 = new String(AESUtil.decrypt(exs));
    System.out.println(str2);
}
```


8. Compile it and execute it with :

```
javac AESUtil.java
java AESUtil
```


9. Flag :
```
HL{R3v3rsing.FUN}
```







### Appendix : Full code used to decrypt the flag

```java
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {
    private static final String ENCRYPTION_IV = "SHCUOkfd89ut7777";
    private static final String ENCRYPTION_KEY = "Simpleji4todnkfL";

    public static byte[] encrypt(byte[] bArr) {
        try {
            Cipher instance = Cipher.getInstance("AES/CBC/PKCS5Padding");
            instance.init(1, makeKey(), makeIv());
            return instance.doFinal(bArr);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decrypt(byte[] bArr) {
        try {
            Cipher instance = Cipher.getInstance("AES/CBC/PKCS5Padding");
            instance.init(2, makeKey(), makeIv());
            return instance.doFinal(bArr);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static AlgorithmParameterSpec makeIv() {
        try {
            return new IvParameterSpec(ENCRYPTION_IV.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    static Key makeKey() {
        try {
            return new SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(ENCRYPTION_KEY.getBytes("UTF-8")), "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (UnsupportedEncodingException e2) {
            e2.printStackTrace();
            return null;
        }
    }
    
    public static void main(String args[]) {
        System.out.println("FLAG:");
        
        byte[] exs = {-28, 73, 79, 78, 113, 73, 101, 98, 115, 6, 27, -35, 111, -55, -114, -11, -29, 0, -73, 91, 115, -24, -4, -94, -59, 43, -57, 112, 11, -54, -115, 2};
        String str2 = new String(AESUtil.decrypt(exs));

        System.out.println(str2);
    }
}
```

