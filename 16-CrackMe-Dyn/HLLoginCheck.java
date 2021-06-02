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
