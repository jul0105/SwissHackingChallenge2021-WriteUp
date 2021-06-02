
// import android.app.Activity;
// import android.net.ConnectivityManager;
// import android.net.NetworkInfo;
// import android.os.AsyncTask;
// import android.util.Log;
// import android.widget.TextView;
// import androidx.lifecycle.LiveData;
// import androidx.lifecycle.MutableLiveData;
// import androidx.lifecycle.ViewModel;
// import java.io.BufferedReader;
// import java.io.IOException;
// import java.io.InputStream;
// import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
// import org.bfe.geoblocking.R;
// import org.bfe.geoblocking.data.model.LoggedInUser;
// import org.json.JSONObject;

public class Solve {
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();


    public static String getMD5(String str) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("MD5");
        instance.update(str.getBytes());
        return bytesToHex(instance.digest());
    }

    public static String bytesToHex(byte[] bArr) {
        char[] cArr = new char[(bArr.length * 2)];
        for (int i = 0; i < bArr.length; i++) {
            int i2 = bArr[i] & 255;
            int i3 = i * 2;
            char[] cArr2 = HEX_ARRAY;
            cArr[i3] = cArr2[i2 >>> 4];
            cArr[i3 + 1] = cArr2[i2 & 15];
        }
        return new String(cArr).toLowerCase();
    }
    
    
    public static void main(String args[]) throws NoSuchAlgorithmException {
        System.out.println("Test");
        String val = "CH.Valais.4000";
        
        System.out.println(getMD5(val));
    }

}
