
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
