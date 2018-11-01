package com.angelsgate.sdk.AngelsGateUtils;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class EncodeAlgorithmUtils {

    private EncodeAlgorithmUtils() {
    }


    public static String computeHash(String text, String salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {

        String base64Text = toBase64(text);
        if (salt.length() % 2 == 0) {
            String result = Rot13(toBase64(SHA256(base64Text + md5(salt))));
            return result;
        } else {
            String result = Rot13(toBase64(SHA256(SHA1(salt) + base64Text)));
            return result;
        }
    }

    public static String toBase64(String message) {
        byte[] data;
        try {
            data = message.getBytes("UTF-8");
            String base64Sms = Base64.encodeToString(data, Base64.NO_WRAP);
            return base64Sms;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static String SHA1(final String text) {
        try {
            MessageDigest md;
            md = MessageDigest.getInstance("SHA-1");
            md.update(text.getBytes("UTF-8"),
                    0, text.length());
            byte[] sha1hash = md.digest();
            return bytesToHex(sha1hash);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static String SHA256(String text) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(text.getBytes("UTF-8"),
                0, text.length());
        byte[] digest = md.digest();
        return bytesToHex(digest);
    }


    public static String md5(String text) throws UnsupportedEncodingException {
        try {
            // Create MD5 Hash
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(text.getBytes("UTF-8"),
                    0, text.length());

            byte messageDigest[] = digest.digest();

            return bytesToHex(messageDigest);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }


    private static String bytesToHex(byte[] bytes) {
        final char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }

        return new String(hexChars);
    }


    public static String Rot13(String input) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 'a' && c <= 'm') c += 13;
            else if (c >= 'A' && c <= 'M') c += 13;
            else if (c >= 'n' && c <= 'z') c -= 13;
            else if (c >= 'N' && c <= 'Z') c -= 13;
            sb.append(c);
        }


        return sb.toString();
    }

    public static String KeyRotational(String Ssalt, String key) {

        String result = (Ssalt + key).substring(0, 16);

        return result;


    }


    public static String SignalKeyRotational(String token, String DeviceId) {

        String result;

        if (token.length() < 8) {
            result = (token + DeviceId).substring(0, 16);

        } else {

            String temp = token.substring(0, 8) + DeviceId;

            for (int i = 0; i < 15; i++) {
                temp += "0";
            }

            result = temp.substring(0, 16);
        }


        return result;


    }






    public static String ServerIvFrag(String newIv, String LastIv) {

        String result = (newIv + LastIv).substring(0, 16);

        return result;

    }
}
