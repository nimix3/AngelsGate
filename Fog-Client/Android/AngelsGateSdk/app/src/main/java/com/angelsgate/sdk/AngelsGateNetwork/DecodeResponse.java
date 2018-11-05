package com.angelsgate.sdk.AngelsGateNetwork;


import android.content.Context;
import android.text.TextUtils;

import com.angelsgate.sdk.AngelsGate;
import com.angelsgate.sdk.AngelsGateNetwork.model.ExchangeTokenRequest;
import com.angelsgate.sdk.AngelsGateNetwork.model.PreAuthDataResponse;
import com.angelsgate.sdk.AngelsGateUtils.AESCrypt;
import com.angelsgate.sdk.AngelsGateUtils.AngelGateConstants;
import com.angelsgate.sdk.AngelsGateUtils.Base64Utils;
import com.angelsgate.sdk.AngelsGateUtils.EncodeAlgorithmUtils;
import com.angelsgate.sdk.AngelsGateUtils.prefs.AngelGatePreferencesHelper;
import com.angelsgate.sdk.ApiInterface;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;

import okhttp3.OkHttpClient;
import okhttp3.ResponseBody;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

/**
 * Created by om on 7/19/2018.
 */

public class DecodeResponse {

    public static String decode(String encryptedResponse, String Ssalt, String mainDeviceId, String methodName, Context ctx) throws GeneralSecurityException {

        JSONObject ModifiedResponseJsonObject = null;
        String iv = AngelGateConstants.iv;


        String secretkey = AngelGateConstants.secretkey;
        String KeyRotational = EncodeAlgorithmUtils.KeyRotational(Ssalt, secretkey);


        String decryptedResponse = null;

        try {
            decryptedResponse = Renc(secretkey, iv, encryptedResponse);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }


        if (decryptedResponse != null) {


            try {
                ModifiedResponseJsonObject = new JSONObject(decryptedResponse);

                ////////////////
                String Signature = ModifiedResponseJsonObject.get("Signature").toString();
                String EncryptedData = ModifiedResponseJsonObject.get("Data").toString();
                String HashedDeviceid = ModifiedResponseJsonObject.get("DeviceidVerify").toString();
                String EncryptedExtra = ModifiedResponseJsonObject.get("Extra").toString();
                long Segment = Long.parseLong(ModifiedResponseJsonObject.get("Seq").toString());
                String TimeRes = ModifiedResponseJsonObject.get("Time").toString();


                ////////
                AngelGatePreferencesHelper.setLastResponseSignature(Signature, ctx);
                ///////////////////


                String serverIv = AngelGateConstants.ServerIv;

                if (serverIv.length() > 0) {
                } else {
                    serverIv = AngelGateConstants.iv;
                }


                if (methodName.equals(AngelGateConstants.PreAuthMethodName)) {


                } else if (methodName.equals(AngelGateConstants.PostAuthMethodName)) {
                    String EncryptedToken = "";
                    EncryptedToken = ModifiedResponseJsonObject.get("Token").toString();

                    String Token = Renc(KeyRotational, serverIv, EncryptedToken);
                    AngelGatePreferencesHelper.setLastToken(Token, ctx);

                } else {

                    String EncryptedToken = "";
                    EncryptedToken = ModifiedResponseJsonObject.get("Token").toString();
                    String newToken = Renc(KeyRotational, serverIv, EncryptedToken);
                    if (newToken != null && newToken.length() > 0) {
                        ExchangeToken(ctx, newToken, mainDeviceId);
                    }
                }


                int currentYear = Calendar.getInstance().get(Calendar.YEAR);
                ///////
                String Base64Data = Renc(KeyRotational, serverIv, EncryptedData);

                String Base64Extra = "";
                if (EncryptedExtra != null && !TextUtils.isEmpty(EncryptedExtra)) {
                    Base64Extra = Renc(KeyRotational, serverIv, EncryptedExtra);
                }


                String Dsig = Dsig(mainDeviceId, Ssalt, Segment);

                //////////////////////////////////////////////////////////////////////////////////
                String EncryptedToken2 = ModifiedResponseJsonObject.get("Token").toString();
                String Token = Renc(KeyRotational, serverIv, EncryptedToken2);
                String ComputedSignature = Ssig(Ssalt, AngelGatePreferencesHelper.getHandler(ctx), Base64Data, currentYear, Segment, Token, TimeRes, methodName, Base64Extra, mainDeviceId);
                boolean checkedAccepted = checkSecurity(Dsig, HashedDeviceid, ComputedSignature, Signature);


                if (checkedAccepted) {

                    ///////////////////////////


                    if (methodName.equals(AngelGateConstants.PreAuthMethodName)) {

                        String preAuthData = Base64Utils.Base64Decode(Base64Data).toString();


                        if (AngelsGate.ErroreHandler(preAuthData)) {

                            PreAuthDataResponse Jsondata = PreAuthDataResponse.JsonToObject(preAuthData);
                            String Handler = Jsondata.getHandler();
                            AngelGatePreferencesHelper.setHandler(Handler, ctx);

                            String ServerIv = Jsondata.getIvr();
                            String ServerIvFrag = EncodeAlgorithmUtils.ServerIvFrag(ServerIv, AngelGateConstants.iv);
                            AngelGateConstants.ServerIv = ServerIvFrag;

                            String ServerPublicKey = Jsondata.getHpub();
                            AngelGateConstants.ServerpublicKey = ServerPublicKey;


                        } else {
                            // error
                        }

                    }

                    return Base64Utils.Base64Decode(Base64Data).toString();

                } else {
                    return "SECURITY_LOCAL_ERROR";
                }


            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (JSONException e) {
                e.printStackTrace();
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }

        }


        return "";
    }


    private static boolean checkSecurity(String Dsig, String HashedDeviceid, String ComputedSignature2, String Signature) {


        if (!HashedDeviceid.equals(Dsig)) {
            return false;
        }

        if (!ComputedSignature2.equals(Signature)) {
            return false;
        }


        return true;
    }


    public static String Renc(String KeyRotational, String iv, String encryptedString) throws GeneralSecurityException {
        return AESCrypt.decrypt(KeyRotational, encryptedString, iv);
    }


    public static String Ssig(String Ss, String handler, String Data, int date, long Seq, String Token, String TimeResponse, String Request, String Extra, String DeviceId) throws UnsupportedEncodingException, NoSuchAlgorithmException {

        return EncodeAlgorithmUtils.computeHash(Ss + handler + Data + date + Seq + Token + TimeResponse + Request + Extra + DeviceId, Ss);
    }


    public static String Dsig(String DeviceId, String Ss, long Segment) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        return EncodeAlgorithmUtils.computeHash(DeviceId + Ss, String.valueOf(Segment));
    }

    public static String Tokenize(String LToken, String CSs) {
        return EncodeAlgorithmUtils.SHA1(LToken + CSs);
    }
    ///////////////

    public static void ExchangeToken(final Context ctx, final String newToken, final String DeviceId) {


        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .addInterceptor(new EncodeRequestInterceptor(ctx))
                .build();


        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl(AngelGateConstants.RetrofiteBaseUrl + "/")
                .client(okHttpClient)
                .addConverterFactory(GsonConverterFactory.create())
                .build();


        final ApiInterface apiInterface = retrofit.create(ApiInterface.class);


        ////RequestHeader
        final long segment = AngelsGate.CreatSegment(ctx);
        final String Ssalt = AngelsGate.CreatSsalt();
        final long TimeStamp = AngelsGate.CreatTimeStamp();
        final String Request = "Exchange";
        final boolean isArrayRequest = false;
        final ExchangeTokenRequest input = new ExchangeTokenRequest(Tokenize(newToken, Ssalt));

        Call<ResponseBody> callback = apiInterface.Exchange(TimeStamp, DeviceId, segment, Ssalt, Request, isArrayRequest, input);
        callback.enqueue(new Callback<ResponseBody>() {


            @Override
            public void onResponse(Call<ResponseBody> call, Response<ResponseBody> response) {

                if (response.isSuccessful()) {

                    String bodyResponse = null;
                    try {
                        bodyResponse = response.body().string();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    String data_response = null;
                    try {
                        data_response = AngelsGate.DecodeResponse(bodyResponse, Ssalt, DeviceId, Request, ctx);
                    } catch (GeneralSecurityException e) {
                        e.printStackTrace();
                    }

                    if (data_response.equals("NOTICE_EXCHANGE_SET")) {
                        AngelGatePreferencesHelper.setLastToken(newToken, ctx);
                    }


                } else {
                    ExchangeToken(ctx, newToken, DeviceId);
                }

            }

            @Override
            public void onFailure(Call<ResponseBody> call, Throwable t) {
                ExchangeToken(ctx, newToken, DeviceId);
            }
        });


    }


}
