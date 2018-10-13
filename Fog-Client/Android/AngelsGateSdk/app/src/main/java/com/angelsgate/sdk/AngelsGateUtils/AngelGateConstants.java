/*
 * Copyright (C) 2017 MINDORKS NEXTGEN PRIVATE LIMITED
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://mindorks.com/license/apache-v2
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.angelsgate.sdk.AngelsGateUtils;

/**
 * Created by amitshekhar on 08/01/17.
 */

public final class AngelGateConstants {

    public static String iv;
    public static String secretkey;
    public static String publicKey;
    public static int MintLengthSsalt;
    public static int MaxLengthSsalt;


    public static String PreAuthMethodName;
    public static String PostAuthMethodName;
    public static String SignalMethodName;
    public static String RetrofiteBaseUrl;

    private AngelGateConstants(AngelGateConstantsBuilder builder) {

        this.publicKey = builder.publicKey;
        this.iv = builder.iv;
        this.secretkey = builder.secretkey;
        this.MintLengthSsalt = builder.MintLengthSsalt;
        this.MaxLengthSsalt = builder.MaxLengthSsalt;

        this.PreAuthMethodName = builder.PreAuthMethodName;
        this.PostAuthMethodName = builder.PostAuthMethodName;
        this.SignalMethodName = builder.SignalMethodName;
        this.RetrofiteBaseUrl = builder.RetrofiteBaseUrl;
    }


    ///////////////////////////////////////////////////
    //Builder Class
    public static class AngelGateConstantsBuilder {

        private String iv = "";
        private String secretkey = "";
        private String publicKey = "";


        private int MintLengthSsalt = 8;
        private int MaxLengthSsalt = 9;

        public static String PreAuthMethodName = "preAuth";
        public static String PostAuthMethodName = "postAuth";
        public static String SignalMethodName = "signal";
        public static String RetrofiteBaseUrl = "";

        public AngelGateConstantsBuilder(String publicKey, String iv, String secretkey, String LoginMethodName, String VerifyLoginMethodName, String BaseUrl) {
            this.publicKey = publicKey;
            this.iv = iv;
            this.secretkey = secretkey;
            this.PreAuthMethodName = LoginMethodName;
            this.PostAuthMethodName = VerifyLoginMethodName;
            this.RetrofiteBaseUrl = BaseUrl;
        }


        public AngelGateConstantsBuilder setMintLengthSsalt(int mintLengthSsalt) {
            this.MintLengthSsalt = mintLengthSsalt;
            return this;
        }

        public AngelGateConstantsBuilder setMaxLengthSsalt(int maxLengthSsalt) {
            this.MaxLengthSsalt = maxLengthSsalt;
            return this;
        }


        public AngelGateConstants build() {
            return new AngelGateConstants(this);
        }

    }
}
