package com.angelsgate.sdk.AngelsGateNetwork.model;

public class ExchangeTokenRequest {

    String TokenValidate;


    public ExchangeTokenRequest(String tokenValidate) {
        TokenValidate = tokenValidate;
    }

    public String getTokenValidate() {
        return TokenValidate;
    }

    public void setTokenValidate(String tokenValidate) {
        TokenValidate = tokenValidate;
    }
}
