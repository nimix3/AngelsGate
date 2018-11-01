package com.angelsgate.sdk.AngelsGateNetwork.model;

import com.google.gson.Gson;

public class PreAuthDataResponse {

    String ivr;
    String hpub;
    String handler;
    String result;

    public String getIvr() {
        return ivr;
    }

    public void setIvr(String ivr) {
        this.ivr = ivr;
    }

    public String getHpub() {
        return hpub;
    }

    public void setHpub(String hpub) {
        this.hpub = hpub;
    }

    public String getHandler() {
        return handler;
    }

    public void setHandler(String handler) {
        this.handler = handler;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }




    ////CREAT BOJECT FROM JSON
    public static PreAuthDataResponse JsonToObject(String JsonString) {

        Gson gson = new Gson();

        PreAuthDataResponse object = gson.fromJson(JsonString, PreAuthDataResponse.class);

        return object;

    }

}
