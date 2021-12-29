package com.yesidentity.sdk.exception;

import com.yesidentity.sdk.invoker.ApiException;

import java.util.List;
import java.util.Map;

public class YesIdentityApiException extends ApiException {

    private String error;
    private String errorDescription;
    private String errorUri;

    public YesIdentityApiException() {
    }

    public YesIdentityApiException(Throwable throwable) {
        super(throwable);
    }

    public YesIdentityApiException(String message) {
        super(message);
    }

    public YesIdentityApiException(String message, Throwable throwable, int code, Map<String, List<String>> responseHeaders, String responseBody) {
        super(message, throwable, code, responseHeaders, responseBody);
    }

    public YesIdentityApiException(String message, int code, Map<String, List<String>> responseHeaders, String responseBody) {
        super(message, code, responseHeaders, responseBody);
    }

    public YesIdentityApiException(String message, Throwable throwable, int code, Map<String, List<String>> responseHeaders) {
        super(message, throwable, code, responseHeaders);
    }

    public YesIdentityApiException(int code, Map<String, List<String>> responseHeaders, String responseBody) {
        super(code, responseHeaders, responseBody);
    }

    public YesIdentityApiException(int code, String message) {
        super(code, message);
    }

    public YesIdentityApiException(int code, String message, Map<String, List<String>> responseHeaders, String responseBody) {
        super(code, message, responseHeaders, responseBody);
    }
}
