package burp;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class AES {

    private static SecretKeySpec secretKey;
    private static byte[] key;

    public static String padKey(String myKey, Integer length) throws UnsupportedEncodingException {
        byte[] key = myKey.getBytes("UTF-8");
        byte[] padKey = null;

        if (length < 0 || !(length % 8 == 0 && length / 8 > 1 && length / 8 < 5)) {
            throw new IllegalArgumentException("Invalid key length. Valid length is 16/24/32");
        }

        if (myKey.length() < length) {
            padKey = Arrays.copyOf(key, length);
            for (int i = myKey.length(); i < length; i++) {
                padKey[i] = 0;
            }
        } else if (myKey.length() == length) {
            padKey = key;
        } else {
            padKey = Arrays.copyOf(key, length);
        }

        return new String(padKey);
    }

    public static void setKey(String myKey, Integer keyLength) throws NoSuchAlgorithmException, UnsupportedEncodingException, IllegalArgumentException {
        MessageDigest sha = null;
        key = padKey(myKey, keyLength).getBytes();
        secretKey = new SecretKeySpec(key, "AES");
    }

    public static String encrypt(String strToEncrypt, String secret, Integer keyLength, String transformations, String iv) throws Exception {
        setKey(secret, keyLength);
        IvParameterSpec ivSpec = null;
        if (iv.length() > 0) {
            ivSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        }
        Cipher cipher = Cipher.getInstance(transformations);
        if (iv.length() > 0) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }
        return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
    }

    public static String decrypt(String strToDecrypt, String secret, Integer keyLength, String transformations, String iv) throws Exception {
        setKey(secret, keyLength);
        IvParameterSpec ivSpec = null;
        if (iv.length() > 0) {
            ivSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        }
        Cipher cipher = Cipher.getInstance(transformations);
        if (iv.length() > 0) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        }
        return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
    }
}