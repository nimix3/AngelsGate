package com.angelsgate.sdk.AngelsGateUtils;

import android.util.Base64;

import java.io.UnsupportedEncodingException;

public class Base64Utils {

    private Base64Utils() {

    }


    public static String Base64Decode(String message) {
        byte[] data = Base64.decode(message, Base64.NO_WRAP);
        try {

            return new String(data, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return null;
    }


    public static byte[] Base64DecodeToByte(String message) {
        byte[] data = Base64.decode(message, Base64.NO_WRAP);
        return data;
    }

    public static String Base64Encode(byte[] data) {
        String base64Sms = Base64.encodeToString(data, Base64.NO_WRAP);
        return base64Sms;
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

}
