package com.angelsgate.sdk.AngelsGateNetwork.model;

public class PreAuthDataRequest {

    String secret;

    public PreAuthDataRequest(String secret) {
        this.secret = secret;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }
}
