# CrackMe Dyn - Android

> Author : jul0105
> Date : 30.05.2021



## Challenge info

**Release** : Bundle 6 (08.05)

**Difficulty** : Hard

**Goal** : Objective: The password is somewhere hidden in this app. Extract it. The correct 6 digit PIN will provide the flag. This app is protected with a basic "anti-root" protection and loads dynamically code.




## Solve

1. First, we decompile the apk using `jadx`
2. Similarly to the others challenges, the login procedure is made in the `org.bfe.crackme.ui.LoginViewModel` class.
3. This class load an encrypted resource (`R.raw.elib`) and decrypt it using the AESUtil class. The decrypted resource is then loaded and the `checkPin` method is executed.
4. The encrypted resource is stored at `resources/res/raw/elib.enc`
5. The `AESUtil` class allow to encrypt and decrypt file but the key and IV are hardcoded. We can just copy this class and add it a main to execute the decryption ourself :
6. We get a `classes.dex` file as an output. We decompile it using `jadx` and we get the `HLLoginCheck.java` which provide the `checkPin` function.
7. This `checkPin` function check the following condition : 25239776756291 mod PIN == 0. If this condition is met, the key is derived from the PIN and used to decrypt an hard-coded ciphertext
8. To find a 6-digit PIN that match the condition, I used this small script :

```python
for i in range(1, 1000000):
    if 25239776756291 % i == 0:
        print(i)
```

9. We find that the PIN is 777737
10. Then, we copy the `HLLoginCheck` class to add a main and call the `checkPin` ourself with PIN 777737.
11. Flag : 

```
HL{C@ll.you.A.M4ster}
```



## Appendix

**Modified `AESUtil.java` :**

```java

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.FileInputStream;


public class AESUtil {
    private static final String ENCRYPTION_IV = "SHCUOkfd89ut34hi";
    private static final String ENCRYPTION_KEY = "Hslgkwji4todnkfL";

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

    public static void encypteFile(File file, File file2) {
        try {
            byte[] readAllBytes = Files.readAllBytes(file.toPath());
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(file2));
            bufferedOutputStream.write(encrypt(readAllBytes));
            bufferedOutputStream.flush();
            bufferedOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void encypteFile(InputStream inputStream, File file) {
        try {
            byte[] bytesFromInputStream = bytesFromInputStream(inputStream);
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(file));
            bufferedOutputStream.write(encrypt(bytesFromInputStream));
            bufferedOutputStream.flush();
            bufferedOutputStream.close();
            inputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void writeDecryptedFile(InputStream inputStream, File file) {
        try {
            byte[] bytesFromInputStream = bytesFromInputStream(inputStream);
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(file));
            bufferedOutputStream.write(decrypt(bytesFromInputStream));
            bufferedOutputStream.flush();
            bufferedOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static byte[] bytesFromInputStream(InputStream inputStream) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] bArr = new byte[8096];
        while (true) {
            int read = inputStream.read(bArr, 0, 8096);
            if (read != -1) {
                byteArrayOutputStream.write(bArr, 0, read);
            } else {
                byteArrayOutputStream.flush();
                return byteArrayOutputStream.toByteArray();
            }
        }
    }
    
    public static void main(String[] args) {
        System.out.println("Hello");
        
        try {
            File file = new File("elib.enc");
            InputStream openRawResource = new FileInputStream(file);
            File createTempFile = new File("result.pt");
            createTempFile.createNewFile();
            AESUtil.writeDecryptedFile(openRawResource, createTempFile);
            System.out.println("OK");
        } catch (Exception e) {
            System.out.println("Erreur");
            System.out.println(e);
        }
        

    }

}
```

Execute with : `javac AESUtil.java && java AESUtil`



**Modified `HLLoginCheck.java` :**

```java
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class HLLoginCheck {
    private static final String ENCRYPTION_IV = "skl5ls74/hdl2HU1";
    static long countWrongTries;
    private static final byte[] e = {103, 44, -118, -71, 82, 112, -94, -2, 8, -52, -81, 114, -106, 23, 125, 46, -41, -15, 97, 35, 32, Byte.MAX_VALUE, -1, 26, -61, 28, Byte.MIN_VALUE, -46, -63, 90, -79, -2};

    public static String checkPin(String str) {
        if (str != null) {
            try {
                if (str.length() >= 4) {
                    Integer valueOf = Integer.valueOf(Integer.parseInt(str));
                    System.out.println("Pin is: " + valueOf);
                    return checkPin(valueOf.intValue());
                }
            } catch (Exception e2) {
                System.out.println("Password must be a PIN.");
                System.out.println("Login error: " + e2.toString());
                return null;
            }
        }
        System.out.println("Pin must be an Integer of 6 digits.");
        return null;
    }

    private static String checkPin(int i) throws InterruptedException {
        BigInteger bigInteger = new BigInteger(String.format("%d", Integer.valueOf(i)));
        if (new BigInteger("25239776756291").mod(bigInteger).intValue() != 0) {
            long j = countWrongTries;
            Thread.sleep(j * j * 200);
            countWrongTries++;
            System.out.println("Wrong PIN.");
            return null;
        }
        countWrongTries = 0;
        return getFlag(bigInteger.multiply(bigInteger).toString());
    }

    private static String getFlag(String str) {
        return new String(decrypt(makeKey(str.getBytes()), e));
    }

    public static byte[] encrypt(Key key, byte[] bArr) {
        try {
            Cipher instance = Cipher.getInstance("AES/CBC/PKCS5Padding");
            instance.init(1, key, makeIv());
            return instance.doFinal(bArr);
        } catch (Exception e2) {
            throw new RuntimeException(e2);
        }
    }

    public static byte[] decrypt(Key key, byte[] bArr) {
        try {
            Cipher instance = Cipher.getInstance("AES/CBC/PKCS5Padding");
            instance.init(2, key, makeIv());
            return instance.doFinal(bArr);
        } catch (Exception e2) {
            throw new RuntimeException(e2);
        }
    }

    static AlgorithmParameterSpec makeIv() {
        try {
            return new IvParameterSpec(ENCRYPTION_IV.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e2) {
            e2.printStackTrace();
            return null;
        }
    }

    static Key makeKey(byte[] bArr) {
        try {
            return new SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(bArr), "AES");
        } catch (NoSuchAlgorithmException e2) {
            e2.printStackTrace();
            return null;
        } catch (Exception e3) {
            e3.printStackTrace();
            return null;
        }
    }
    
    public static void main(String[] args) {
        System.out.println("Hellooo");
        try {
            System.out.println(checkPin(777737));
        } catch (InterruptedException e) {
            System.out.println(e);
        }
        
    }

}
```

Execute with : `javac HLLoginCheck.java && java HLLoginCheck`