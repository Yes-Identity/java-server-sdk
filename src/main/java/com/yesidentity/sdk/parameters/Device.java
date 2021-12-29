package com.yesidentity.sdk.parameters;

public class Device {

    private final String name;
    private final String publicKey;
    private final Boolean biometricsEnabled;

    private String phoneNumber;
    private String registrationToken;
    private String securityCode;

    public Device(String name, String publicKey, Boolean biometricsEnabled) {
        this.name = name;
        this.publicKey = publicKey;
        this.biometricsEnabled = biometricsEnabled;
    }

    public Device registrationToken(String registrationToken) {
        this.registrationToken = registrationToken;
        return this;
    }

    public Device phoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
        return this;
    }

    public Device securityCode(String securityCode) {
        this.securityCode = securityCode;
        return this;
    }

    public String getName() {
        return name;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public Boolean getBiometricsEnabled() {
        return biometricsEnabled;
    }

    public String getRegistrationToken() {
        return registrationToken;
    }

    public String getSecurityCode() {
        return securityCode;
    }
}
