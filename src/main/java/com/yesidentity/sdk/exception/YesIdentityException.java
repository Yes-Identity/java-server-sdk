package com.yesidentity.sdk.exception;

public class YesIdentityException extends Exception {

  public YesIdentityException() {}

  public YesIdentityException(String message) {
    super(message);
  }

  public YesIdentityException(String message, Throwable cause) {
    super(message, cause);
  }

  public YesIdentityException(Throwable cause) {
    super(cause);
  }

  public YesIdentityException(
      String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
