package com.angelsgate.sdk.AngelsGateUtils;

import android.util.Base64;



import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by om on 7/23/2018.
 */

public class RSACrypt {

    public static String RSAEncrypt(final String plain) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

        PublicKey publicKey = getPublicKey(AngelGateConstants.publicKey);
        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plain.getBytes("UTF-8"));
        String encoded = Base64Utils.Base64Encode(encryptedBytes);
        return encoded;
    }

    public static String RSADecrypt(final String EncodedText, String privateKeyString) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

        PrivateKey privateKey = getPrivateKey(privateKeyString);

        byte[] encryptedBytes = EncodedText.getBytes("UTF-8");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        String decrypted = new String(decryptedBytes);

        return decrypted;
    }

    public static PublicKey getPublicKey(String key) {
        try {
             byte[] byteKey = Base64.decode(key.getBytes("UTF-8"), Base64.NO_WRAP);
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(X509publicKey);
            return publicKey;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public static PrivateKey getPrivateKey(String key) {
        try {
            byte[] byteKey = Base64.decode(key.getBytes("UTF-8"), Base64.NO_WRAP);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privKey = kf.generatePrivate(keySpec);
            return privKey;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

}
