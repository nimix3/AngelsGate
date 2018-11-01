package com.angelsgate.sdk.AngelsGateUtils;

import android.content.Context;
import android.util.Base64;

import com.angelsgate.sdk.AngelsGateUtils.prefs.AngelGatePreferencesHelper;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Created by om on 7/23/2018.
 */

public class RSACrypt {

    public static String RSAEncrypt(final String plain) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {

        PublicKey publicKey;

        if (AngelGateConstants.ServerpublicKey.length() > 0) {
            publicKey = getPublicKey(AngelGateConstants.ServerpublicKey);
        } else {

            publicKey = getPublicKey(AngelGateConstants.publicKey);
        }

        //////////////////////
        Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
        oaepFromInit.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
        byte[] encryptedBytes = oaepFromInit.doFinal(plain.getBytes("UTF-8"));
        String encoded = Base64Utils.Base64Encode(encryptedBytes);
        ////////////////////

        return encoded;
    }


    public static String RSAEncryptByte(final String plain, Context ctx) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

        PublicKey publicKey;

        if (AngelGatePreferencesHelper.getPublicKeyGenerated(ctx).length() > 0) {
            publicKey = getPublicKey(AngelGatePreferencesHelper.getPublicKeyGenerated(ctx));
        } else {

            publicKey = getPublicKey(AngelGateConstants.publicKey);
        }


        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plain.getBytes("UTF-8"));
        String encoded = Base64Utils.Base64Encode(encryptedBytes);
        return encoded;
    }


    public static String RSADecryptByte(final byte[] encryptedBytes, String privateKeyString) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {

        PrivateKey privateKey = getPrivateKey(privateKeyString);
        //////////////////////
        Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
        oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        byte[] decryptedBytes = oaepFromInit.doFinal(encryptedBytes);
        String decrypted = new String(decryptedBytes, "UTF-8");
        return decrypted;

    }


    public static String RSADecrypt(final String EncodedText, String privateKeyString) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

        PrivateKey privateKey = getPrivateKey(privateKeyString);

        byte[] encryptedBytes = EncodedText.getBytes("UTF-8");

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding");
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


    public static void GenerateRsaKey(Context ctx) {


        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024); // You can set a different value here

            KeyPair kp = kpg.generateKeyPair();
            PrivateKey prk = kp.getPrivate();
            PublicKey puk = kp.getPublic();


            AngelGatePreferencesHelper.setPrivateKeyGenerated(Base64Utils.Base64Encode(prk.getEncoded()), ctx);
            AngelGatePreferencesHelper.setPublicKeyGenerated(Base64Utils.Base64Encode(puk.getEncoded()), ctx);

        } catch (Exception e) {
            System.out.println(e);
        }


    }
}
