package com.angelsgate.sdk.AngelsGateUtils.prefs;

import android.content.Context;
import android.content.SharedPreferences;

import com.angelsgate.sdk.AngelsGateUtils.AngelGateConstants;
import com.angelsgate.sdk.AngelsGateUtils.RandomUtils;

public class AngelGatePreferencesHelper {

    private static final String PREF_KEY_LAST_TOKEN = "PREF_KEY_ANGELS_GATE_LAST_TOKEN";
    private static final String PREF_KEY_LAST_REQUEST_SIGNATURE = "PREF_KEY_ANGELS_GATE_LAST_REQUEST_SIGNATURE";
    private static final String PREF_KEY_LAST_RESPONSE_SIGNATURE = "PREF_KEY_ANGELS_GATE_LAST_RESPONSE_SIGNATURE";
    private static final String PREF_KEY_SEGMENT = "PREF_KEY_SEGMENT";
    ///////////////////////
    private static final String PREF_KEY_HANDLER = "PREF_KEY_HANDLER";

    private static final String PREF_KEY_PUBLIC_KEY_GENERATED = "PREF_KEY_PUBLIC_KEY_GENERATED";
    private static final String PREF_KEY_PRIVATE_KEY_GENERATED = "PREF_KEY_PRIVATE_KEY_GENERATED";



    public static void ResetAllData(Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        mPrefs.edit().putString(PREF_KEY_LAST_TOKEN, "").apply();
        mPrefs.edit().putString(PREF_KEY_LAST_REQUEST_SIGNATURE, "").apply();
        mPrefs.edit().putString(PREF_KEY_LAST_RESPONSE_SIGNATURE, "").apply();

        ///
        mPrefs.edit().putLong(PREF_KEY_SEGMENT, 0).apply();
        mPrefs.edit().putString(PREF_KEY_HANDLER, RandomUtils.randomAlphaNumeric(20)).apply();
        mPrefs.edit().putString(PREF_KEY_PUBLIC_KEY_GENERATED, "").apply();
        mPrefs.edit().putString(PREF_KEY_PRIVATE_KEY_GENERATED, "").apply();

        /////
        AngelGateConstants.ServerIv="";
        AngelGateConstants.ServerpublicKey="";

    }



    public static String getLastToken(Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        return mPrefs.getString(PREF_KEY_LAST_TOKEN, "");
    }


    public static void setLastToken(String LastToken, Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        mPrefs.edit().putString(PREF_KEY_LAST_TOKEN, LastToken).apply();
    }


    public static void setLastRequestSignature(String LastSignature, Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        mPrefs.edit().putString(PREF_KEY_LAST_REQUEST_SIGNATURE, LastSignature).apply();

    }


    public static String getLastRequestSignature(Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        return mPrefs.getString(PREF_KEY_LAST_REQUEST_SIGNATURE, "");
    }


    public static void setLastResponseSignature(String LastSignature, Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        mPrefs.edit().putString(PREF_KEY_LAST_RESPONSE_SIGNATURE, LastSignature).apply();

    }


    public static String getLastResponseSignature(Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        return mPrefs.getString(PREF_KEY_LAST_RESPONSE_SIGNATURE, "");
    }



    public static long getSegment(Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        return mPrefs.getLong(PREF_KEY_SEGMENT, 0);
    }


    public static void setSegment(long segment, Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        mPrefs.edit().putLong(PREF_KEY_SEGMENT, segment).apply();
    }




///////////////////////////////////////
    public static String getHandler(Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        return mPrefs.getString(PREF_KEY_HANDLER, RandomUtils.randomAlphaNumeric(20));
    }


    public static void setHandler(String handler, Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        mPrefs.edit().putString(PREF_KEY_HANDLER, handler).apply();
    }


    public static String getPublicKeyGenerated(Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        return mPrefs.getString(PREF_KEY_PUBLIC_KEY_GENERATED, "");
    }


    public static void setPublicKeyGenerated(String publickey, Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        mPrefs.edit().putString(PREF_KEY_PUBLIC_KEY_GENERATED, publickey).apply();
    }


    public static String getPrivateKeyGenerated(Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        return mPrefs.getString(PREF_KEY_PRIVATE_KEY_GENERATED, "");
    }


    public static void setPrivateKeyGenerated(String Private, Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        mPrefs.edit().putString(PREF_KEY_PRIVATE_KEY_GENERATED, Private).apply();
    }
}
