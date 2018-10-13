package com.angelsgate.sdk.AngelsGateUtils;

public class AngelGateErroreHandler {

    public static final String ERROR_SERVER_FATAL = "ERROR_SERVER_FATAL";
    public static final String ERROR_INPUT_EMPTY = "ERROR_INPUT_EMPTY";
    public static final String ERROR_INPUT_INVALID = "ERROR_INPUT_INVALID";
    public static final String ERROR_INPUT_UNKNOW = "ERROR_INPUT_UNKNOW";
    public static final String ERROR_INPUT_BLOCKED = "ERROR_INPUT_BLOCKED";
    public static final String ERROR_INPUT_BROKEN = "ERROR_INPUT_BROKEN";
    public static final String ERROR_INPUT_CRACKED = "ERROR_INPUT_CRACKED";
    public static final String ERROR_INPUT_INVALIDTIME = "ERROR_INPUT_INVALIDTIME";
    public static final String ERROR_INPUT_INVALIDHASH = "ERROR_INPUT_INVALIDHASH";
    public static final String ERROR_INPUT_INVALIDTOKEN = "ERROR_INPUT_INVALIDTOKEN";
    public static final String ERROR_INPUT_INVALIDCHAIN = "ERROR_INPUT_INVALIDCHAIN";
    public static final String ERROR_INPUT_INVALIDROUTE = "ERROR_INPUT_INVALIDROUTE";
    public static final String ERROR_INPUT_INVALIDEXCHANGE = "ERROR_INPUT_INVALIDEXCHANGE";
    public static final String ERROR_SESSION_INVALID = "ERROR_SESSION_INVALID";
    public static final String NOTICE_DATA_EMPTY = "NOTICE_DATA_EMPTY";
    public static final String NOTICE_EXCHANGE_SET = "NOTICE_EXCHANGE_SET";
    public static final String ERROR_INPUT_BADREQUEST = "ERROR_INPUT_BADREQUEST";

    ////////////////////////////////////////////////////////////////

    public static final String SIGNAL_NO_UPDATE = "SIGNAL_NO_UPDATE";
    public static final String SIGNAL_ERROR = "SIGNAL_ERROR";
    public static final String SIGNAL_ERROR_RECEIVE_PACKAGE = "SIGNAL_ERROR_RECEIVE_PACKAGE";
    public static final String SIGNAL_ERROR_INPUT_EMPTY = "SIGNAL_ERROR_INPUT_EMPTY";
    public static final String SIGNAL_ERROR_NOIDENTIFIER = "SIGNAL_ERROR_NOIDENTIFIER";
    public static final String SIGNAL_ERROR_SESSION_INVALID = "SIGNAL_ERROR_SESSION_INVALID";
    public static final String SIGNAL_ERROR_TIME_INVALID = "SIGNAL_ERROR_TIME_INVALID";
    public static final String SIGNAL_ERROR_INPUT_CRACKED = "SIGNAL_ERROR_INPUT_CRACKED";
    public static final String SIGNAL_ERROR_ANALYSIS_PACKAGE = "SIGNAL_ERROR_ANALYSIS_PACKAGE";
    public static final String SIGNAL_ERROR_IP_BLOCKED = "SIGNAL_ERROR_IP_BLOCKED";
    public static final String SIGNAL_ERROR_INVALID_METHOD = "SIGNAL_ERROR_INVALID_METHOD";
    public static final String SIGNAL_ERROR_SERVER_FATAL = "SIGNAL_ERROR_SERVER_FATAL";


    public static boolean ErrorHandler(String respose) {

        switch (respose) {
            case ERROR_SERVER_FATAL:
                return false;

            case ERROR_INPUT_EMPTY:
                return false;


            case ERROR_INPUT_INVALID:
                return false;


            case ERROR_INPUT_UNKNOW:
                return false;


            case ERROR_INPUT_BLOCKED:
                return false;


            case ERROR_INPUT_BROKEN:
                return false;


            case ERROR_INPUT_CRACKED:
                return false;

            case ERROR_INPUT_INVALIDTIME:
                return false;


            case ERROR_INPUT_INVALIDHASH:
                return false;


            case ERROR_INPUT_INVALIDTOKEN:
                return false;

            case ERROR_INPUT_INVALIDCHAIN:
                return false;


            case ERROR_INPUT_INVALIDROUTE:
                return false;

            case ERROR_INPUT_INVALIDEXCHANGE:
                return false;

            case ERROR_SESSION_INVALID:
                return false;

            case NOTICE_DATA_EMPTY:
                return false;


            case NOTICE_EXCHANGE_SET:
                return false;

            case ERROR_INPUT_BADREQUEST:
                return false;

            default:
                return true;
        }
    }


    public static String SignalErrorHandler(int respose) {

        switch (respose) {
            case 0:
                return SIGNAL_NO_UPDATE;

            case -1:
                return SIGNAL_ERROR;


            case -2:
                return SIGNAL_ERROR_RECEIVE_PACKAGE;

            case -3:
                return SIGNAL_ERROR_INPUT_EMPTY;

            case -4:
                return SIGNAL_ERROR_NOIDENTIFIER;

            case -5:
                return SIGNAL_ERROR_SESSION_INVALID;

            case -6:
                return SIGNAL_ERROR_TIME_INVALID;

            case -7:
                return SIGNAL_ERROR_INPUT_CRACKED;


            case -8:
                return SIGNAL_ERROR_ANALYSIS_PACKAGE;


            case -9:
                return SIGNAL_ERROR_IP_BLOCKED;

            case -10:
                return SIGNAL_ERROR_INVALID_METHOD;

            case -11:
                return SIGNAL_ERROR_SERVER_FATAL;

        }
        return "";
    }
}
