package com.angelsgate.sdk;


import com.angelsgate.sdk.AngelsGateNetwork.model.ExchangeTokenRequest;
import com.angelsgate.sdk.AngelsGateNetwork.model.LogDataRequest;
import com.angelsgate.sdk.AngelsGateNetwork.model.TestDataRequest;

import okhttp3.ResponseBody;
import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.Header;
import retrofit2.http.POST;


public interface ApiInterface {


    @POST("App.php")
    Call<ResponseBody> PreAuth(@Header("Timestamp") long timestamp, @Header("DeviceId") String deviceId, @Header("Segment") long segment, @Header("Ssalt") String Ssalt, @Header("Request") String nameMethode, @Header("isArrayResponse") boolean isArrayResponse );


    @POST("App.php")
    Call<ResponseBody> PostAuth(@Header("Timestamp") long timestamp, @Header("DeviceId") String deviceId, @Header("Segment") long segment, @Header("Ssalt") String Ssalt, @Header("Request") String nameMethode, @Header("isArrayResponse") boolean isArrayResponse);

    @POST("App.php")
    Call<ResponseBody> Exchange(@Header("Timestamp") long timestamp, @Header("DeviceId") String deviceId, @Header("Segment") long segment, @Header("Ssalt") String Ssalt, @Header("Request") String nameMethode, @Header("isArrayResponse") boolean isArrayResponse, @Body ExchangeTokenRequest input);


    @POST("App.php")
    Call<ResponseBody> TestApi(@Header("Timestamp") long timestamp, @Header("DeviceId") String deviceId, @Header("Segment") long segment, @Header("Ssalt") String Ssalt, @Header("Request") String nameMethode, @Header("isArrayResponse") boolean isArrayResponse, @Body TestDataRequest input);


    @POST("Signal.php")
    Call<ResponseBody> signal(@Header("Timestamp") long timestamp, @Header("DeviceId") String deviceId, @Header("Segment") long segment, @Header("Ssalt") String Ssalt, @Header("Request") String nameMethode, @Header("isArrayResponse") boolean isArrayResponse, @Body TestDataRequest input);


    @POST("Log.php")
    Call<ResponseBody> Log(@Body LogDataRequest input);


}
