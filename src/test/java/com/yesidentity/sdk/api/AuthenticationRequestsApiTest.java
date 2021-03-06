/*
 * Yes Identity
 * Welcome to Yes Identity API documentation.
 *
 * The version of the OpenAPI document: 1.0
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.yesidentity.sdk.api;

import com.yesidentity.sdk.invoker.ApiException;
import com.yesidentity.sdk.model.AuthenticationRequestModel;
import com.yesidentity.sdk.model.ErrorResponseModel;
import com.yesidentity.sdk.model.InlineObjectModel;
import org.junit.Test;
import org.junit.Ignore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * API tests for AuthenticationRequestsApi
 */
@Ignore
public class AuthenticationRequestsApiTest {

    private final AuthenticationRequestsApi api = new AuthenticationRequestsApi();

    
    /**
     * Approve Authentication Request
     *
     * Approve Authentication Request
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @Test
    public void approveAuthenticationRequestTest() throws ApiException {
        String deviceId = null;
        String authReqId = null;
        InlineObjectModel inlineObjectModel = null;
                api.approveAuthenticationRequest(deviceId, authReqId, inlineObjectModel);
        // TODO: test validations
    }
    
    /**
     * Deny Authentication Request
     *
     * Deny Authentication Request
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @Test
    public void denyAuthenticationRequestTest() throws ApiException {
        String deviceId = null;
        String authReqId = null;
                api.denyAuthenticationRequest(deviceId, authReqId);
        // TODO: test validations
    }
    
    /**
     * Get Authentication Request
     *
     * Get Authentication Request
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @Test
    public void getAuthenticationRequestTest() throws ApiException {
        String deviceId = null;
        String authReqId = null;
                AuthenticationRequestModel response = api.getAuthenticationRequest(deviceId, authReqId);
        // TODO: test validations
    }
    
}
