package com.yesidentity.sdk;

import com.yesidentity.sdk.api.*;
import com.yesidentity.sdk.exception.YesIdentityApiException;
import com.yesidentity.sdk.exception.YesIdentityException;
import com.yesidentity.sdk.helper.YesIdentityHelpers;
import com.yesidentity.sdk.invoker.ApiClient;
import com.yesidentity.sdk.invoker.ApiException;
import com.yesidentity.sdk.model.*;
import com.yesidentity.sdk.parameters.Attribute;
import com.yesidentity.sdk.parameters.AuthenticationRequest;
import com.yesidentity.sdk.parameters.Device;
import com.yesidentity.sdk.parameters.TokenRequest;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class YesIdentity {

    private static final Integer ACCESS_TOKEN_EXPIRATION = 5;

    private final String clientId;
    private final String privateKey;
    private final String baseUrl;
    private final String basePath;

    public YesIdentity(String clientId, String privateKey, String baseUrl) {
        this.clientId = clientId;
        this.privateKey = privateKey;
        this.baseUrl = baseUrl;
        this.basePath = baseUrl;
    }

    public YesIdentity(String clientId, File privateKey, String baseUrl) throws YesIdentityException {
        this.clientId = clientId;
        this.baseUrl = baseUrl;
        this.basePath = baseUrl;
        try {
            this.privateKey = new String(Files.readAllBytes(Paths.get(privateKey.getPath())));
        } catch (IOException e) {
            throw new YesIdentityException("Error reading private key file.", e);
        }
    }

    public YesIdentity(String clientId, String privateKey) {
        this(clientId, privateKey, "https://api.yesidentity.com/");
    }

    public YesIdentity(String clientId, File privateKey) throws YesIdentityException {
        this(clientId, privateKey, "https://api.yesidentity.com/");
    }

    /**
     * Initiate Authentication Request
     *
     * @param authenticationRequest
     * @return AuthenticationResponse
     * @throws YesIdentityApiException
     * @throws YesIdentityException
     */
    public AuthenticationResponseModel initiateAuthenticationRequest(
            AuthenticationRequest authenticationRequest)
            throws YesIdentityApiException, YesIdentityException {

        AuthorizationApi authorizationApi = new AuthorizationApi();

        ApiClient apiClient = authorizationApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        try {
            Set<String> scopeSet = new HashSet<>(Set.of(OpenIDConfigurationModel.ScopesSupportedEnum.OPENID.getValue()));

            if (authenticationRequest.getScope() != null) {
                scopeSet.add(authenticationRequest.getScope().getValue());
            }
            return authorizationApi.initiateAuthenticationRequest(
                    String.join(" ", scopeSet),
                    authenticationRequest.getBindingMessage(),
                    null,
                    authenticationRequest.getLoginHint(),
                    authenticationRequest.getRequestedExpiry(),
                    authenticationRequest.getClientNotificationToken(),
                    getClientId(),
                    YesIdentityHelpers.createClientAssertion(getPrivateKey(), getBaseUrl(), getClientId(), Collections.emptyMap(), ACCESS_TOKEN_EXPIRATION),
                    ClientAssertionTypeModel.URN_IETF_PARAMS_OAUTH_CLIENT_ASSERTION_TYPE_JWT_BEARER,
                    null,
                    null
            );
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Initiate Token Request
     *
     * @param tokenRequest
     * @return TokenResponse
     * @throws YesIdentityException
     * @throws YesIdentityApiException
     */
    public TokenResponseModel initiateTokenRequest(TokenRequest tokenRequest)
            throws YesIdentityException, YesIdentityApiException {
        AuthorizationApi authorizationApi = new AuthorizationApi();

        ApiClient apiClient = authorizationApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        try {
            TokenResponseModel tokenResponseModel =
                    authorizationApi.initiateTokenRequest(
                            tokenRequest.getGrantType().getValue(),
                            tokenRequest.getAuthReqId(),
                            tokenRequest.getScope(),
                            getClientId(),
                            YesIdentityHelpers.createClientAssertion(getPrivateKey(), getBaseUrl(), getClientId(), Collections.emptyMap(), ACCESS_TOKEN_EXPIRATION),
                            ClientAssertionTypeModel.URN_IETF_PARAMS_OAUTH_CLIENT_ASSERTION_TYPE_JWT_BEARER);
            YesIdentityHelpers.verifyToken(tokenResponseModel.getAccessToken(), getBasePath() + "/v1/auth/.well-known/jwks.json", getBaseUrl(), getBaseUrl());
            return tokenResponseModel;
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Get JSON Web Key Set
     *
     * @return JSONWebKeySet
     * @throws YesIdentityApiException
     */
    public JSONWebKeySetModel getJSONWebKeySet() throws YesIdentityApiException {
        AuthorizationApi authorizationApi = new AuthorizationApi();

        ApiClient apiClient = authorizationApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        try {
            return authorizationApi.getJSONWebKeySet();
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Get OpenID Configuration
     *
     * @return OpenIDConfigurationModel
     * @throws YesIdentityApiException
     */
    public OpenIDConfigurationModel getOpenIDConfiguration() throws YesIdentityApiException {
        AuthorizationApi authorizationApi = new AuthorizationApi();

        ApiClient apiClient = authorizationApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        try {
            return authorizationApi.getOpenIDConfiguration();
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Create Device
     *
     * @param username
     * @param device
     * @return DeviceModel
     * @throws YesIdentityApiException
     * @throws YesIdentityException
     */
    public DeviceModel createDevice(String username, Device device)
            throws YesIdentityApiException, YesIdentityException {

        DevicesApi devicesApi = new DevicesApi();

        ApiClient apiClient = devicesApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(YesIdentityHelpers.createClientAssertion(getPrivateKey(), getBaseUrl(), getClientId(), Collections.emptyMap(), ACCESS_TOKEN_EXPIRATION));

        try {
            return devicesApi.createDevice(username, new DeviceModel()
                    .securityCode(device.getSecurityCode())
                    .phoneNumber(device.getPhoneNumber())
                    .name(device.getName())
                    .publicKey(device.getPublicKey())
                    .biometricsEnabled(device.getBiometricsEnabled())
                    .registrationToken(device.getRegistrationToken()));
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Get Devices
     *
     * @param username
     * @param active
     * @param blocked
     * @return List<DeviceModel>
     * @throws YesIdentityException
     * @throws YesIdentityApiException
     */
    public List<DeviceModel> getDevices(String username, Boolean active, Boolean blocked)
            throws YesIdentityException, YesIdentityApiException {

        DevicesApi devicesApi = new DevicesApi();

        ApiClient apiClient = devicesApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(YesIdentityHelpers.createClientAssertion(getPrivateKey(), getBaseUrl(), getClientId(), Collections.emptyMap(), ACCESS_TOKEN_EXPIRATION));
        try {
            return devicesApi.getDevices(username, active, blocked);
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Get Device
     *
     * @param username
     * @param deviceId
     * @return DeviceModel
     * @throws YesIdentityException
     * @throws YesIdentityApiException
     */
    public DeviceModel getDevice(String username, String deviceId)
            throws YesIdentityException, YesIdentityApiException {
        DevicesApi devicesApi = new DevicesApi();

        ApiClient apiClient = devicesApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(YesIdentityHelpers.createClientAssertion(getPrivateKey(), getBaseUrl(), getClientId(), Collections.emptyMap(), ACCESS_TOKEN_EXPIRATION));

        try {
            return devicesApi.getDevice(username, deviceId);
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Delete Device
     *
     * @param username
     * @param deviceId
     * @throws YesIdentityException
     * @throws YesIdentityApiException
     */
    public void deleteDevice(String username, String deviceId) throws YesIdentityException, YesIdentityApiException {
        DevicesApi devicesApi = new DevicesApi();

        ApiClient apiClient = devicesApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(YesIdentityHelpers.createClientAssertion(getPrivateKey(), getBaseUrl(), getClientId(), Collections.emptyMap(), ACCESS_TOKEN_EXPIRATION));

        try {
            devicesApi.deleteDevice(username, deviceId);
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Activate Device
     *
     * @param username
     * @param deviceId
     * @return DeviceModel
     * @throws YesIdentityException
     * @throws YesIdentityApiException
     */
    public DeviceModel activateDevice(String username, String deviceId)
            throws YesIdentityException, YesIdentityApiException {
        DevicesApi devicesApi = new DevicesApi();

        ApiClient apiClient = devicesApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(YesIdentityHelpers.createClientAssertion(getPrivateKey(), getBaseUrl(), getClientId(), Collections.emptyMap(), ACCESS_TOKEN_EXPIRATION));

        try {
            return devicesApi.activateDevice(username, deviceId);
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * De-activate Device
     *
     * @param username
     * @param deviceId
     * @return DeviceModel
     * @throws YesIdentityException
     * @throws YesIdentityApiException
     */
    public DeviceModel deactivateDevice(String username, String deviceId)
            throws YesIdentityException, YesIdentityApiException {
        DevicesApi devicesApi = new DevicesApi();

        ApiClient apiClient = devicesApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(YesIdentityHelpers.createClientAssertion(getPrivateKey(), getBaseUrl(), getClientId(), Collections.emptyMap(), ACCESS_TOKEN_EXPIRATION));

        try {
            return devicesApi.deactivateDevice(username, deviceId);
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Block Device
     *
     * @param username
     * @param deviceId
     * @return DeviceModel
     * @throws YesIdentityException
     * @throws YesIdentityApiException
     */
    public DeviceModel blockDevice(String username, String deviceId)
            throws YesIdentityException, YesIdentityApiException {
        DevicesApi devicesApi = new DevicesApi();

        ApiClient apiClient = devicesApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(YesIdentityHelpers.createClientAssertion(getPrivateKey(), getBaseUrl(), getClientId(), Collections.emptyMap(), ACCESS_TOKEN_EXPIRATION));

        try {
            return devicesApi.blockDevice(username, deviceId);
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Unblock Device
     *
     * @param username
     * @param deviceId
     * @return DeviceModel
     * @throws YesIdentityException
     * @throws YesIdentityApiException
     */
    public DeviceModel unblockDevice(String username, String deviceId)
            throws YesIdentityException, YesIdentityApiException {
        DevicesApi devicesApi = new DevicesApi();

        ApiClient apiClient = devicesApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(YesIdentityHelpers.createClientAssertion(getPrivateKey(), getBaseUrl(), getClientId(), Collections.emptyMap(), ACCESS_TOKEN_EXPIRATION));

        try {
            return devicesApi.unblockDevice(username, deviceId);
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Create Attribute
     *
     * @param username
     * @param attribute
     * @return DeviceModel
     * @throws YesIdentityException
     * @throws YesIdentityApiException
     */
    public AttributeModel createAttribute(String username, Attribute attribute)
            throws YesIdentityException, YesIdentityApiException {
        AttributesApi attributesApi = new AttributesApi();

        ApiClient apiClient = attributesApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(YesIdentityHelpers.createClientAssertion(getPrivateKey(), getBaseUrl(), getClientId(), Collections.emptyMap(), ACCESS_TOKEN_EXPIRATION));

        try {
            return attributesApi.createAttribute(username, new AttributeModel().name(attribute.getName()).value(attribute.getValue()));
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Create Attribute
     *
     * @param username
     * @param name
     * @return DeviceModel
     * @throws YesIdentityException
     * @throws YesIdentityApiException
     */
    public AttributeModel getAttribute(String username, String name)
            throws YesIdentityException, YesIdentityApiException {
        AttributesApi attributesApi = new AttributesApi();

        ApiClient apiClient = attributesApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(YesIdentityHelpers.createClientAssertion(getPrivateKey(), getBaseUrl(), getClientId(), Collections.emptyMap(), ACCESS_TOKEN_EXPIRATION));

        try {
            return attributesApi.getAttribute(username, name);
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Get Attributes
     *
     * @param username
     * @return List<Attribute>
     * @throws YesIdentityException
     * @throws YesIdentityApiException
     */
    public List<AttributeModel> getAttributes(String username)
            throws YesIdentityException, YesIdentityApiException {
        AttributesApi attributesApi = new AttributesApi();

        ApiClient apiClient = attributesApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(YesIdentityHelpers.createClientAssertion(getPrivateKey(), getBaseUrl(), getClientId(), Collections.emptyMap(), ACCESS_TOKEN_EXPIRATION));

        try {
            return attributesApi.getAttributes(username);
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Delete Attribute
     *
     * @param username
     * @param name
     * @throws YesIdentityException
     * @throws YesIdentityApiException
     */
    public void getAttributes(String username, String name)
            throws YesIdentityException, YesIdentityApiException {
        AttributesApi attributesApi = new AttributesApi();

        ApiClient apiClient = attributesApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(YesIdentityHelpers.createClientAssertion(getPrivateKey(), getBaseUrl(), getClientId(), Collections.emptyMap(), ACCESS_TOKEN_EXPIRATION));

        try {
            attributesApi.deleteAttribute(username, name);
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Get Authentication Request
     *
     * @param deviceId
     * @param authReqId
     * @param authToken
     * @return AuthenticationRequestModel
     * @throws YesIdentityException
     * @throws YesIdentityApiException
     */
    public AuthenticationRequestModel getAuthenticationRequest(
            String deviceId, String authReqId, String authToken)
            throws YesIdentityException, YesIdentityApiException {

        AuthenticationRequestsApi authenticationRequestsApi = new AuthenticationRequestsApi();

        ApiClient apiClient = authenticationRequestsApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(authToken);

        try {
            return authenticationRequestsApi.getAuthenticationRequest(deviceId, authReqId);
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Deny Authentication Request
     *
     * @param deviceId
     * @param authReqId
     * @param authToken
     * @throws YesIdentityApiException
     */
    public void denyAuthenticationRequest(String deviceId, String authReqId, String authToken)
            throws YesIdentityApiException {
        AuthenticationRequestsApi authenticationRequestsApi = new AuthenticationRequestsApi();

        ApiClient apiClient = authenticationRequestsApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(authToken);

        try {
            authenticationRequestsApi.denyAuthenticationRequest(deviceId, authReqId);
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Approve Authentication Request
     *
     * @param deviceId
     * @param authReqId
     * @param authToken
     * @param signature
     * @throws YesIdentityApiException
     */
    public void approveAuthenticationRequest(
            String deviceId, String authReqId, String authToken, String signature)
            throws YesIdentityApiException {
        AuthenticationRequestsApi authenticationRequestsApi = new AuthenticationRequestsApi();

        ApiClient apiClient = authenticationRequestsApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        apiClient.setBearerToken(authToken);

        try {
            authenticationRequestsApi.approveAuthenticationRequest(deviceId, authReqId, new InlineObjectModel().signature(signature));
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Create QR Code
     *
     * @param authToken
     * @param size
     * @return File
     * @throws YesIdentityApiException
     */
    public File createQRCode(String authToken, Integer size) throws YesIdentityApiException {
        QrCodeApi qrCodeApi = new QrCodeApi();

        ApiClient apiClient = qrCodeApi.getApiClient();
        apiClient.setBasePath(getBasePath());

        try {
            return qrCodeApi.createQRCode(authToken, size);
        } catch (ApiException e) {
            throw new YesIdentityApiException(e.getResponseBody());
        }
    }

    /**
     * Create QR Code
     *
     * @param authToken
     * @return File
     * @throws YesIdentityApiException
     */
    public File createQRCode(String authToken) throws YesIdentityApiException {
        return createQRCode(authToken, null);
    }

    /**
     * Get Client ID
     *
     * @return String
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Get Base Url
     *
     * @return String
     */
    public String getBaseUrl() {
        return baseUrl;
    }

    /**
     * Get Private Key
     *
     * @return String
     */
    public String getPrivateKey() {
        return privateKey;
    }

    /**
     * Get Base Path
     *
     * @return String
     */
    public String getBasePath() {
        return basePath;
    }

}
