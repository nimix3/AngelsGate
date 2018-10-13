package com.angelsgate.sdk.AngelsGateNetwork;

import android.content.Context;

import com.angelsgate.sdk.AngelsGateUtils.AESCrypt;
import com.angelsgate.sdk.AngelsGateUtils.AngelGateConstants;
import com.angelsgate.sdk.AngelsGateUtils.Base64Utils;
import com.angelsgate.sdk.AngelsGateUtils.EncodeAlgorithmUtils;
import com.angelsgate.sdk.AngelsGateUtils.RSACrypt;
import com.angelsgate.sdk.AngelsGateUtils.prefs.AngelGatePreferencesHelper;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okio.Buffer;


public class EncodeRequestInterceptor implements Interceptor {
    Context context;

    public EncodeRequestInterceptor(Context context) {
        this.context = context;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request originalRequest = chain.request();
        return chain.proceed(EncodeRetrofitRequest(originalRequest));
    }


    private Request EncodeRetrofitRequest(Request retrofitRequest) throws UnsupportedEncodingException {
        RequestBody requestBody = retrofitRequest.body();
        String rawJson = bodyToString(requestBody);

        String CToken = "";
        String CChain = "";
        String ChainInSig = "";


        long Segment = Long.parseLong(retrofitRequest.header("Segment"));
        String Ssalt = retrofitRequest.header("Ssalt");
        String Request = retrofitRequest.header("Request");
        String DeviceId = retrofitRequest.header("DeviceId");
        long timestamp = Long.parseLong(retrofitRequest.header("Timestamp"));
        boolean isArray = Boolean.parseBoolean(retrofitRequest.header("isArrayRequest"));


        if (!Request.equals(AngelGateConstants.SignalMethodName)) {


            String ObjectORArray = "";

            if (isArray) {
                ObjectORArray = "Array";
            } else {
                ObjectORArray = "Object";
            }


            JSONObject originalRequestJsonObject = null;
            JSONArray originalRequestJsonArray = null;


            if (rawJson.length() != 0) {
                try {

                    if (ObjectORArray.equals("Object")) {
                        originalRequestJsonObject = new JSONObject(rawJson);
                    } else if (ObjectORArray.equals("Array")) {
                        originalRequestJsonArray = new JSONArray(rawJson);
                    }

                } catch (JSONException e) {
                    e.printStackTrace();


                }
            }


            JSONObject ModifiedRequestJsonObject = new JSONObject();


            try {


                String iv = AngelGateConstants.iv;
                String secretkey = AngelGateConstants.secretkey;
                String KeyRotational = EncodeAlgorithmUtils.KeyRotational(Ssalt, secretkey);

                String data = "";

                if (ObjectORArray.equals("Object")) {

                    if (originalRequestJsonObject != null) {
                        try {
                            data = Renc(KeyRotational, iv, Base64Utils.toBase64(originalRequestJsonObject.toString()));
                        } catch (GeneralSecurityException e) {
                            e.printStackTrace();
                        }
                    } else {

                        try {
                            data = Renc(KeyRotational, iv, Base64Utils.toBase64(""));
                        } catch (GeneralSecurityException e) {
                            e.printStackTrace();
                        }
                    }


                } else if (ObjectORArray.equals("Array")) {

                    if (originalRequestJsonArray != null) {
                        try {
                            data = Renc(KeyRotational, iv, Base64Utils.toBase64(originalRequestJsonArray.toString()));
                        } catch (GeneralSecurityException e) {
                            e.printStackTrace();
                        }
                    } else {

                        try {
                            data = Renc(KeyRotational, iv, Base64Utils.toBase64(""));
                        } catch (GeneralSecurityException e) {
                            e.printStackTrace();
                        }
                    }


                }

                ModifiedRequestJsonObject.put("Request", Request);
                ModifiedRequestJsonObject.put("Data", data);
                ModifiedRequestJsonObject.put("Deviceid", Renc(KeyRotational, iv, DeviceId));
                ModifiedRequestJsonObject.put("Ssalt", RSA(Ssalt));
                ModifiedRequestJsonObject.put("Time", timestamp);
                ModifiedRequestJsonObject.put("Seq", Segment);


                ////////////////////////////////////

                if (Request.equals(AngelGateConstants.PreAuthMethodName) || Request.equals(AngelGateConstants.PostAuthMethodName)) {

                    ModifiedRequestJsonObject.put("Token", "");
                    ModifiedRequestJsonObject.put("Chain", "");
                    ChainInSig = "";

                } else {

                    String LastToken = AngelGatePreferencesHelper.getLastToken(context);

                    if (LastToken.length() > 0) {

                        CToken = Tokenize(LastToken, Ssalt);
                        ModifiedRequestJsonObject.put("Token", CToken);

                    } else {

                    }


                    String LastRequestSignature = AngelGatePreferencesHelper.getLastRequestSignature(context);
                    String LastResponseSignature = AngelGatePreferencesHelper.getLastResponseSignature(context);

                    ChainInSig = LastRequestSignature + ",,," + LastResponseSignature;
                    CChain = Renc(KeyRotational, iv, LastRequestSignature + ",,," + LastResponseSignature);
                    ModifiedRequestJsonObject.put("Chain", CChain);
                }


                ///////////////////


                int currentYear = Calendar.getInstance().get(Calendar.YEAR);


                try {


                    if (ObjectORArray.equals("Object")) {

                        if (originalRequestJsonObject != null) {


                            if (Request.equals(AngelGateConstants.PreAuthMethodName) || Request.equals(AngelGateConstants.PostAuthMethodName)) {


                                String sig = Csig(Ssalt, currentYear, Request, Base64Utils.toBase64(originalRequestJsonObject.toString()),
                                        DeviceId, "", ChainInSig, Segment, timestamp);


                                ModifiedRequestJsonObject.put("Signature", sig);
                                AngelGatePreferencesHelper.setLastRequestSignature(sig, context);


                            } else {

                                String LastToken = AngelGatePreferencesHelper.getLastToken(context);

                                String sig = Csig(Ssalt, currentYear, Request, Base64Utils.toBase64(originalRequestJsonObject.toString()),
                                        DeviceId, LastToken, ChainInSig, Segment, timestamp);


                                ModifiedRequestJsonObject.put("Signature", sig);
                                AngelGatePreferencesHelper.setLastRequestSignature(sig, context);
                            }


                        } else {


                            if (Request.equals(AngelGateConstants.PreAuthMethodName) || Request.equals(AngelGateConstants.PostAuthMethodName)) {


                                String sig = Csig(Ssalt, currentYear, Request, Base64Utils.toBase64(""),
                                        DeviceId, "", ChainInSig, Segment, timestamp);

                                ModifiedRequestJsonObject.put("Signature", sig);
                                AngelGatePreferencesHelper.setLastRequestSignature(sig, context);


                            } else {

                                String LastToken = AngelGatePreferencesHelper.getLastToken(context);
                                String sig = Csig(Ssalt, currentYear, Request, Base64Utils.toBase64(""),
                                        DeviceId, LastToken, ChainInSig, Segment, timestamp);

                                ModifiedRequestJsonObject.put("Signature", sig);
                                AngelGatePreferencesHelper.setLastRequestSignature(sig, context);
                            }


                        }


                    } else if (ObjectORArray.equals("Array")) {


                        if (originalRequestJsonArray != null) {


                            if (Request.equals(AngelGateConstants.PreAuthMethodName) || Request.equals(AngelGateConstants.PostAuthMethodName)) {


                                String sig = Csig(Ssalt, currentYear, Request, Base64Utils.toBase64(originalRequestJsonArray.toString()),
                                        DeviceId, "", ChainInSig, Segment, timestamp);


                                ModifiedRequestJsonObject.put("Signature", sig);
                                AngelGatePreferencesHelper.setLastRequestSignature(sig, context);


                            } else {

                                String LastToken = AngelGatePreferencesHelper.getLastToken(context);
                                String sig = Csig(Ssalt, currentYear, Request, Base64Utils.toBase64(originalRequestJsonArray.toString()),
                                        DeviceId, LastToken, ChainInSig, Segment, timestamp);

                                ModifiedRequestJsonObject.put("Signature", sig);
                                AngelGatePreferencesHelper.setLastRequestSignature(sig, context);
                            }


                        } else {


                            if (Request.equals(AngelGateConstants.PreAuthMethodName) || Request.equals(AngelGateConstants.PostAuthMethodName)) {


                                String sig = Csig(Ssalt, currentYear, Request, Base64Utils.toBase64(""),
                                        DeviceId, "", ChainInSig, Segment, timestamp);


                                ModifiedRequestJsonObject.put("Signature", sig);
                                AngelGatePreferencesHelper.setLastRequestSignature(sig, context);


                            } else {


                                String LastToken = AngelGatePreferencesHelper.getLastToken(context);
                                String sig = Csig(Ssalt, currentYear, Request, Base64Utils.toBase64(""),
                                        DeviceId, LastToken, ChainInSig, Segment, timestamp);

                                ModifiedRequestJsonObject.put("Signature", sig);
                                AngelGatePreferencesHelper.setLastRequestSignature(sig, context);


                            }


                        }


                    }


                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }


            } catch (JSONException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }


            String iv = AngelGateConstants.iv;
            String secretkey = AngelGateConstants.secretkey;


            String originalString = ModifiedRequestJsonObject.toString();
            String encryptedString = null;
            try {
                encryptedString = Senc(secretkey, iv, originalString);

            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }


            Request compressedRequest = retrofitRequest.newBuilder()
                    .method(retrofitRequest.method(), RequestBody.create(retrofitRequest.body().contentType(), encryptedString))
                    .header("Segment", String.valueOf(0))
                    .header("Ssalt", String.valueOf(0))
                    .header("Request", "")
                    .header("DeviceId", "")
                    .header("Timestamp", "")
                    .header("isArrayRequest", "")
                    .build();

            return compressedRequest;


        } else {

            ///SIGNAL
            String ObjectORArray = "";

            if (isArray) {
                ObjectORArray = "Array";
            } else {
                ObjectORArray = "Object";
            }


            JSONObject originalRequestJsonObject = null;
            JSONArray originalRequestJsonArray = null;


            if (rawJson.length() != 0) {
                try {

                    if (ObjectORArray.equals("Object")) {
                        originalRequestJsonObject = new JSONObject(rawJson);
                    } else if (ObjectORArray.equals("Array")) {
                        originalRequestJsonArray = new JSONArray(rawJson);
                    }

                } catch (JSONException e) {
                    e.printStackTrace();


                }
            }


            JSONObject ModifiedRequestJsonObject = new JSONObject();


            try {


                String LastToken = AngelGatePreferencesHelper.getLastToken(context);

                String iv = AngelGateConstants.iv;
                String secretkey = AngelGateConstants.secretkey;
                String KeyRotational = EncodeAlgorithmUtils.SignalKeyRotational(LastToken, DeviceId);


                String data = "";

                if (ObjectORArray.equals("Object")) {

                    if (originalRequestJsonObject != null) {
                        try {
                            data = Nenc(KeyRotational, iv, Base64Utils.toBase64(originalRequestJsonObject.toString()));
                        } catch (GeneralSecurityException e) {
                            e.printStackTrace();
                        }
                    } else {

                        try {
                            data = Nenc(KeyRotational, iv, Base64Utils.toBase64(""));
                        } catch (GeneralSecurityException e) {
                            e.printStackTrace();
                        }
                    }


                } else if (ObjectORArray.equals("Array")) {

                    if (originalRequestJsonArray != null) {
                        try {
                            data = Nenc(KeyRotational, iv, Base64Utils.toBase64(Base64Utils.toBase64(originalRequestJsonArray.toString())));
                        } catch (GeneralSecurityException e) {
                            e.printStackTrace();
                        }
                    } else {

                        try {
                            data = Nenc(KeyRotational, iv, Base64Utils.toBase64(""));
                        } catch (GeneralSecurityException e) {
                            e.printStackTrace();
                        }
                    }


                }


                ModifiedRequestJsonObject.put("Identifier", Nsig(DeviceId, LastToken));
                ModifiedRequestJsonObject.put("Data", data);
                ModifiedRequestJsonObject.put("Time", timestamp);

                ////////////////////////////////////


                try {


                    if (ObjectORArray.equals("Object")) {

                        if (originalRequestJsonObject != null) {


                            String sig = Msig(DeviceId, Base64Utils.toBase64(originalRequestJsonObject.toString()), String.valueOf(timestamp)
                                    , LastToken);


                            ModifiedRequestJsonObject.put("Signature", sig);
                            AngelGatePreferencesHelper.setLastRequestSignature(sig, context);

                        } else {

                            String sig = Msig(DeviceId, Base64Utils.toBase64(""), String.valueOf(timestamp)
                                    , LastToken);

                            ModifiedRequestJsonObject.put("Signature", sig);
                            AngelGatePreferencesHelper.setLastRequestSignature(sig, context);
                        }


                    } else if (ObjectORArray.equals("Array")) {


                        if (originalRequestJsonArray != null) {


                            String sig = Msig(DeviceId, Base64Utils.toBase64(originalRequestJsonArray.toString()), String.valueOf(timestamp)
                                    , LastToken);

                            ModifiedRequestJsonObject.put("Signature", sig);
                            AngelGatePreferencesHelper.setLastRequestSignature(sig, context);
                        } else {

                            String sig = Msig(DeviceId, Base64Utils.toBase64(""), String.valueOf(timestamp)
                                    , LastToken);
                            ModifiedRequestJsonObject.put("Signature", sig);
                            AngelGatePreferencesHelper.setLastRequestSignature(sig, context);
                        }


                    }

                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }


            } catch (JSONException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }


            String iv = AngelGateConstants.iv;
            String secretkey = AngelGateConstants.secretkey;


            String originalString = ModifiedRequestJsonObject.toString();
            String encryptedString = null;
            try {
                encryptedString = Senc(secretkey, iv, originalString);

            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }


            Request compressedRequest = retrofitRequest.newBuilder()
                    .method(retrofitRequest.method(), RequestBody.create(requestBody.contentType(), encryptedString))
                    .header("Segment", String.valueOf(0))
                    .header("Ssalt", String.valueOf(0))
                    .header("Request", "")
                    .header("DeviceId", "")
                    .header("Timestamp", "")
                    .header("isArrayRequest", "")
                    .build();

            return compressedRequest;


        }


    }


    public static String bodyToString(final RequestBody request) {
        try {
            final RequestBody copy = request;
            final Buffer buffer = new Buffer();
            if (copy != null)
                copy.writeTo(buffer);
            else
                return "";
            return buffer.readUtf8();
        } catch (final IOException e) {
            return "did not work";
        }
    }


    public static String Renc(String Key, String iv, String encryptedString) throws GeneralSecurityException {
        return AESCrypt.encrypt(Key, encryptedString, iv);
    }


    public static String Csig(String Ss, int date, String Request, String Data, String DeviceId, String Token, String Chain, long Seq, long TimeResponse) throws UnsupportedEncodingException, NoSuchAlgorithmException {

        String CToken;
        if (Token.length() > 0) {
            CToken = Tokenize(Token, Ss);
        } else {
            CToken = "";
        }

        return EncodeAlgorithmUtils.computeHash(Ss + date + Request + Data + DeviceId + CToken + Chain + Seq + TimeResponse, Ss);
    }


    public static String RSA(String input) throws NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        return RSACrypt.RSAEncrypt(input);
    }


    public static String Tokenize(String LToken, String CSs) {
        return EncodeAlgorithmUtils.SHA1(LToken + CSs);
    }

    public static String Senc(String Key, String iv, String encryptedString) throws GeneralSecurityException {
        return AESCrypt.encrypt(Key, encryptedString, iv);
    }


    //////////////////////Signal method

    public static String Msig(String DeviceId, String Data, String time, String token) throws UnsupportedEncodingException, NoSuchAlgorithmException {


        return EncodeAlgorithmUtils.computeHash(DeviceId + Data + time, token);
    }

    public static String Nenc(String Key, String iv, String encryptedString) throws GeneralSecurityException {
        return AESCrypt.encrypt(Key, encryptedString, iv);
    }


    public static String Nsig(String DeviceId, String Token) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        return EncodeAlgorithmUtils.computeHash(DeviceId, Token);
    }

}