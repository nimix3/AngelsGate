package com.angelsgate.sdk;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;

import com.angelsgate.sdk.AngelsGateNetwork.EncodeRequestInterceptor;
import com.angelsgate.sdk.AngelsGateNetwork.model.TestDataRequest;
import com.angelsgate.sdk.AngelsGateUtils.AngelGateConstants;
import com.angelsgate.sdk.AngelsGateUtils.RandomUtils;
import com.angelsgate.sdk.AngelsGateUtils.prefs.AngelGatePreferencesHelper;

import java.io.IOException;
import java.security.GeneralSecurityException;

import okhttp3.OkHttpClient;
import okhttp3.ResponseBody;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

public class MainActivity extends AppCompatActivity {

    ApiInterface apiInterface;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        ////////////////
        Button preAuth_button = (Button) findViewById(R.id.preAuth);
        Button postAuth_button = (Button) findViewById(R.id.postAuth);
        Button test_button = (Button) findViewById(R.id.test);
        Button signal_button = (Button) findViewById(R.id.signal);


        final String deviceId = RandomUtils.randomAlphaNumeric(30);

        preAuth_button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                preAuth(deviceId);
            }
        });


        postAuth_button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                postAuth(deviceId);
            }
        });


        test_button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                test(deviceId);
            }
        });

        signal_button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                signal(deviceId);
            }
        });


        String baseUrl = "https://example.com/api";
        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .addInterceptor(new EncodeRequestInterceptor(getApplicationContext()))
                .build();


        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl(baseUrl + "/")
                .client(okHttpClient)
                .addConverterFactory(GsonConverterFactory.create())
                .build();


        apiInterface = retrofit.create(ApiInterface.class);


        //////////////

        String iv = "";
        String SecretKey = "";
        String PublicKey ="";


        AngelGateConstants angel = new AngelGateConstants.AngelGateConstantsBuilder(
                PublicKey, iv, SecretKey, "PreAuth", "PostAuth", baseUrl)
                .setMaxLengthSsalt(14)
                .setMintLengthSsalt(16)
                .build();


        /////////////////
        ////RequestHeader
//        final long segment = AngelsGate.CreatSegment(MainActivity.this);
//        final String Ssalt = AngelsGate.CreatSsalt();
//        final long TimeStamp = AngelsGate.CreatTimeStamp();
//        final String Request = "Test";
//        boolean isArrayRequest = false;
//        final String DeviceId = "123456";


//        TestDataRequest input = new TestDataRequest("HELLO");
//        try {
//            Response<ResponseBody> response = apiInterface.TestApi(TimeStamp, DeviceId, segment, Ssalt, Request, isArrayRequest,input).execute();
//            if (response.isSuccessful()) {
//                String bodyResponse = response.body().string();
//                String data_response = AngelsGate.DecodeResponse(bodyResponse, Ssalt, DeviceId, Request, MainActivity.this);
//                AngelsGate.ErroreHandler(data_response);
//            }
//
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (GeneralSecurityException e) {
//            e.printStackTrace();
//        }


        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        ////RequestHeader
//        final long segment = AngelsGate.CreatSegment(MainActivity.this);
//        final String Ssalt = AngelsGate.CreatSsalt();
//        final long TimeStamp = AngelsGate.CreatTimeStamp();
//        final String Request = "Test";
//        boolean isArrayRequest = false;
//        final String DeviceId = "123456";
//
//
//        OkHttpClient client = new OkHttpClient();
//
//        //add parameters
//        HttpUrl.Builder urlBuilder = HttpUrl.parse("https://www.example.com").newBuilder();
//        urlBuilder.addQueryParameter("query", "example");
//
//
//        String url = urlBuilder.build().toString();
//
//        //build the request
//        Request request = new Request.Builder().url(url).build();
//
//
//        try {
//            request = AngelsGate.EncodeRequest(request, TimeStamp, DeviceId, segment, Ssalt, Request, isArrayRequest, getApplicationContext());
//        } catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
//        } catch (GeneralSecurityException e) {
//            e.printStackTrace();
//        }
//
//
//        //execute
//        try {
//            okhttp3.Response response2 = client.newCall(request).execute();
//
//            String bodyResponse = response2.body().string();
//            String data_response = AngelsGate.DecodeResponse(bodyResponse, Ssalt, DeviceId, Request, MainActivity.this);
//            AngelsGate.ErroreHandler(data_response);
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (GeneralSecurityException e) {
//            e.printStackTrace();
//        }
//

    }


    public void preAuth( String deviceId) {

        AngelGatePreferencesHelper.ResetAllData(MainActivity.this);
        ///PreAuth
        ////RequestHeader
        final long segment = AngelsGate.CreatSegment(MainActivity.this);
        final String Ssalt = AngelsGate.CreatSsalt();
        final long TimeStamp = AngelsGate.CreatTimeStamp();
        final String Request = "PreAuth";
        boolean isArrayRequest = false;
        final String DeviceId = deviceId;


        Call<ResponseBody> callback = apiInterface.PreAuth(TimeStamp, DeviceId, segment, Ssalt, Request, isArrayRequest);
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
                    try {

                      
                        if (AngelsGate.StringErroreHandler(bodyResponse)) {

                            String data_response = AngelsGate.DecodeResponse(bodyResponse, Ssalt, DeviceId, Request, MainActivity.this);

                            AngelsGate.ErroreHandler(data_response);

                        } else {


                        }


                    } catch (GeneralSecurityException e) {
                        e.printStackTrace();
                    }


                } else {
                    System.out.println("preAuth error" );
                }

            }

            @Override
            public void onFailure(Call<ResponseBody> call, Throwable t) {
                System.out.println("preAuth error222" );
            }
        });


    }

    public void postAuth( String deviceId) {

        ////PostAuth
        ////RequestHeader
        final long segment2 = AngelsGate.CreatSegment(MainActivity.this);
        final String Ssalt2 = AngelsGate.CreatSsalt();
        final long TimeStamp2 = AngelsGate.CreatTimeStamp();
        final String Request2 = "PostAuth";
        boolean isArrayRequest2 = false;
        final String DeviceId2 = deviceId;


        Call<ResponseBody> callback2 = apiInterface.PostAuth(TimeStamp2, DeviceId2, segment2, Ssalt2, Request2, isArrayRequest2);
        callback2.enqueue(new Callback<ResponseBody>() {


            @Override
            public void onResponse(Call<ResponseBody> call, Response<ResponseBody> response) {

                if (response.isSuccessful()) {

                    String bodyResponse = null;
                    try {
                        bodyResponse = response.body().string();

                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    try {


                        if (AngelsGate.StringErroreHandler(bodyResponse)) {

                            String data_response = AngelsGate.DecodeResponse(bodyResponse, Ssalt2, DeviceId2, Request2, MainActivity.this);

                            AngelsGate.ErroreHandler(data_response);

                        } else {


                        }


                    } catch (GeneralSecurityException e) {
                        e.printStackTrace();
                    }


                } else {

                }

            }

            @Override
            public void onFailure(Call<ResponseBody> call, Throwable t) {

            }
        });
    }

    public void test( String deviceId) {
        ///TestApi
        ////RequestHeader
        final long segment3 = AngelsGate.CreatSegment(MainActivity.this);
        final String Ssalt3 = AngelsGate.CreatSsalt();
        final long TimeStamp3 = AngelsGate.CreatTimeStamp();
        final String Request3 = "checkUpdate";
        boolean isArrayRequest3 = false;
        final String DeviceId3 = deviceId;

        TestDataRequest input = new TestDataRequest("hello");

        Call<ResponseBody> callback3 = apiInterface.TestApi(TimeStamp3, DeviceId3, segment3, Ssalt3, Request3, isArrayRequest3, input);
        callback3.enqueue(new Callback<ResponseBody>() {


            @Override
            public void onResponse(Call<ResponseBody> call, Response<ResponseBody> response) {


                if (response.isSuccessful()) {

                    String bodyResponse = null;
                    try {
                        bodyResponse = response.body().string();


                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    try {


                        if (AngelsGate.StringErroreHandler(bodyResponse)) {

                            String data_response = AngelsGate.DecodeResponse(bodyResponse, Ssalt3, DeviceId3, Request3, MainActivity.this);

                            AngelsGate.ErroreHandler(data_response);

                        } else {


                        }


                    } catch (GeneralSecurityException e) {
                        e.printStackTrace();
                    }


                } else {

                }
            }

            @Override
            public void onFailure(Call<ResponseBody> call, Throwable t) {

            }
        });


    }


    public void signal( String deviceId) {
        ///signal
        ////RequestHeader
        final long segment4 = AngelsGate.CreatSegment(MainActivity.this);
        final String Ssalt4 = AngelsGate.CreatSsalt();
        final long TimeStamp4 = AngelsGate.CreatTimeStamp();
        final String Request4 = AngelGateConstants.SignalMethodName;
        boolean isArrayRequest4 = false;
        final String DeviceId4 = deviceId;

        TestDataRequest input = new TestDataRequest("HELLO");


        Call<ResponseBody> callback3 = apiInterface.signal(TimeStamp4, DeviceId4, segment4, Ssalt4, Request4, isArrayRequest4, input);
        callback3.enqueue(new Callback<ResponseBody>() {


            @Override
            public void onResponse(Call<ResponseBody> call, Response<ResponseBody> response) {

                if (response.isSuccessful()) {


                    String bodyResponse = null;
                    try {
                        bodyResponse = response.body().string();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    boolean error = AngelsGate.ErroreHandler(bodyResponse);


                    if (!error) {
                        ///ERROR IN RESPONSE
                    } else {

                        if (Integer.parseInt(bodyResponse) > 0) {

                            //ACTION
                        } else {
                            String SignalError = AngelsGate.SignalErroreHandler(Integer.parseInt(bodyResponse));

                        }

                    }


                } else {


                }
            }

            @Override
            public void onFailure(Call<ResponseBody> call, Throwable t) {

            }
        });


    }


}
