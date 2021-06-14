
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSA {
    public RSA() {
    }

    public static String encrypt(String text, PublicKey key) {
        byte[] cipherText = null;

        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(1, key);
            cipherText = cipher.doFinal(text.getBytes("UTF-8"));
        } catch (Exception var4) {
            var4.printStackTrace();
        }

        return Base64.encode(cipherText);
    }

    public static byte[] encrypt_byte(byte[] text, PublicKey key) {
        byte[] cipherText = text;

        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(1, key);
            cipherText = cipher.doFinal(cipherText);
        } catch (Exception var4) {
            var4.printStackTrace();
        }

        return cipherText;
    }

    public static String decrypt(String text, PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        byte[] dectyptedText = Base64.decode(text);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(2, key);
        return new String(cipher.doFinal(dectyptedText), "UTF-8");
    }

    public static byte[] decrypt_byte(byte[] text, PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(2, key);
        return cipher.doFinal(text);
    }
}
