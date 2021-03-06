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

import com.yesidentity.sdk.invoker.ApiCallback;
import com.yesidentity.sdk.invoker.ApiClient;
import com.yesidentity.sdk.invoker.ApiException;
import com.yesidentity.sdk.invoker.ApiResponse;
import com.yesidentity.sdk.invoker.Configuration;
import com.yesidentity.sdk.invoker.Pair;
import com.yesidentity.sdk.invoker.ProgressRequestBody;
import com.yesidentity.sdk.invoker.ProgressResponseBody;

import com.google.gson.reflect.TypeToken;

import java.io.IOException;


import com.yesidentity.sdk.model.AuthenticationResponseModel;
import com.yesidentity.sdk.model.ClientAssertionTypeModel;
import com.yesidentity.sdk.model.ErrorResponseModel;
import com.yesidentity.sdk.model.JSONWebKeySetModel;
import com.yesidentity.sdk.model.OpenIDConfigurationModel;
import com.yesidentity.sdk.model.TokenResponseModel;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AuthorizationApi {
    private ApiClient localVarApiClient;
    private int localHostIndex;
    private String localCustomBaseUrl;

    public AuthorizationApi() {
        this(Configuration.getDefaultApiClient());
    }

    public AuthorizationApi(ApiClient apiClient) {
        this.localVarApiClient = apiClient;
    }

    public ApiClient getApiClient() {
        return localVarApiClient;
    }

    public void setApiClient(ApiClient apiClient) {
        this.localVarApiClient = apiClient;
    }

    public int getHostIndex() {
        return localHostIndex;
    }

    public void setHostIndex(int hostIndex) {
        this.localHostIndex = hostIndex;
    }

    public String getCustomBaseUrl() {
        return localCustomBaseUrl;
    }

    public void setCustomBaseUrl(String customBaseUrl) {
        this.localCustomBaseUrl = customBaseUrl;
    }

    /**
     * Build call for getJSONWebKeySet
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call getJSONWebKeySetCall(final ApiCallback _callback) throws ApiException {
        String basePath = null;

        // Operation Servers
        String[] localBasePaths = new String[] {  };

        // Determine Base Path to Use
        if (localCustomBaseUrl != null){
            basePath = localCustomBaseUrl;
        } else if ( localBasePaths.length > 0 ) {
            basePath = localBasePaths[localHostIndex];
        } else {
            basePath = null;
        }

        Object localVarPostBody = null;

        // create path and map variables
        String localVarPath = "/v1/auth/.well-known/jwks.json";

        List<Pair> localVarQueryParams = new ArrayList<Pair>();
        List<Pair> localVarCollectionQueryParams = new ArrayList<Pair>();
        Map<String, String> localVarHeaderParams = new HashMap<String, String>();
        Map<String, String> localVarCookieParams = new HashMap<String, String>();
        Map<String, Object> localVarFormParams = new HashMap<String, Object>();

        final String[] localVarAccepts = {
            "application/json"
        };
        final String localVarAccept = localVarApiClient.selectHeaderAccept(localVarAccepts);
        if (localVarAccept != null) {
            localVarHeaderParams.put("Accept", localVarAccept);
        }

        final String[] localVarContentTypes = {
            
        };
        final String localVarContentType = localVarApiClient.selectHeaderContentType(localVarContentTypes);
        if (localVarHeaderParams != null) {
            localVarHeaderParams.put("Content-Type", localVarContentType);
        }

        String[] localVarAuthNames = new String[] {  };
        return localVarApiClient.buildCall(basePath, localVarPath, "GET", localVarQueryParams, localVarCollectionQueryParams, localVarPostBody, localVarHeaderParams, localVarCookieParams, localVarFormParams, localVarAuthNames, _callback);
    }

    @SuppressWarnings("rawtypes")
    private okhttp3.Call getJSONWebKeySetValidateBeforeCall(final ApiCallback _callback) throws ApiException {
        

        okhttp3.Call localVarCall = getJSONWebKeySetCall(_callback);
        return localVarCall;

    }

    /**
     * Get JSON Web Key Set
     * Get JSON Web Key Set
     * @return JSONWebKeySetModel
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public JSONWebKeySetModel getJSONWebKeySet() throws ApiException {
        ApiResponse<JSONWebKeySetModel> localVarResp = getJSONWebKeySetWithHttpInfo();
        return localVarResp.getData();
    }

    /**
     * Get JSON Web Key Set
     * Get JSON Web Key Set
     * @return ApiResponse&lt;JSONWebKeySetModel&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<JSONWebKeySetModel> getJSONWebKeySetWithHttpInfo() throws ApiException {
        okhttp3.Call localVarCall = getJSONWebKeySetValidateBeforeCall(null);
        Type localVarReturnType = new TypeToken<JSONWebKeySetModel>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * Get JSON Web Key Set (asynchronously)
     * Get JSON Web Key Set
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call getJSONWebKeySetAsync(final ApiCallback<JSONWebKeySetModel> _callback) throws ApiException {

        okhttp3.Call localVarCall = getJSONWebKeySetValidateBeforeCall(_callback);
        Type localVarReturnType = new TypeToken<JSONWebKeySetModel>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
    /**
     * Build call for getOpenIDConfiguration
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call getOpenIDConfigurationCall(final ApiCallback _callback) throws ApiException {
        String basePath = null;

        // Operation Servers
        String[] localBasePaths = new String[] {  };

        // Determine Base Path to Use
        if (localCustomBaseUrl != null){
            basePath = localCustomBaseUrl;
        } else if ( localBasePaths.length > 0 ) {
            basePath = localBasePaths[localHostIndex];
        } else {
            basePath = null;
        }

        Object localVarPostBody = null;

        // create path and map variables
        String localVarPath = "/v1/auth/.well-known/openid-configuration";

        List<Pair> localVarQueryParams = new ArrayList<Pair>();
        List<Pair> localVarCollectionQueryParams = new ArrayList<Pair>();
        Map<String, String> localVarHeaderParams = new HashMap<String, String>();
        Map<String, String> localVarCookieParams = new HashMap<String, String>();
        Map<String, Object> localVarFormParams = new HashMap<String, Object>();

        final String[] localVarAccepts = {
            "application/json"
        };
        final String localVarAccept = localVarApiClient.selectHeaderAccept(localVarAccepts);
        if (localVarAccept != null) {
            localVarHeaderParams.put("Accept", localVarAccept);
        }

        final String[] localVarContentTypes = {
            
        };
        final String localVarContentType = localVarApiClient.selectHeaderContentType(localVarContentTypes);
        if (localVarHeaderParams != null) {
            localVarHeaderParams.put("Content-Type", localVarContentType);
        }

        String[] localVarAuthNames = new String[] {  };
        return localVarApiClient.buildCall(basePath, localVarPath, "GET", localVarQueryParams, localVarCollectionQueryParams, localVarPostBody, localVarHeaderParams, localVarCookieParams, localVarFormParams, localVarAuthNames, _callback);
    }

    @SuppressWarnings("rawtypes")
    private okhttp3.Call getOpenIDConfigurationValidateBeforeCall(final ApiCallback _callback) throws ApiException {
        

        okhttp3.Call localVarCall = getOpenIDConfigurationCall(_callback);
        return localVarCall;

    }

    /**
     * Get OpenID Configuration
     * Get OpenID Configuration
     * @return OpenIDConfigurationModel
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public OpenIDConfigurationModel getOpenIDConfiguration() throws ApiException {
        ApiResponse<OpenIDConfigurationModel> localVarResp = getOpenIDConfigurationWithHttpInfo();
        return localVarResp.getData();
    }

    /**
     * Get OpenID Configuration
     * Get OpenID Configuration
     * @return ApiResponse&lt;OpenIDConfigurationModel&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<OpenIDConfigurationModel> getOpenIDConfigurationWithHttpInfo() throws ApiException {
        okhttp3.Call localVarCall = getOpenIDConfigurationValidateBeforeCall(null);
        Type localVarReturnType = new TypeToken<OpenIDConfigurationModel>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * Get OpenID Configuration (asynchronously)
     * Get OpenID Configuration
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call getOpenIDConfigurationAsync(final ApiCallback<OpenIDConfigurationModel> _callback) throws ApiException {

        okhttp3.Call localVarCall = getOpenIDConfigurationValidateBeforeCall(_callback);
        Type localVarReturnType = new TypeToken<OpenIDConfigurationModel>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
    /**
     * Build call for initiateAuthenticationRequest
     * @param scope The scope of the access request (required)
     * @param bindingMessage Message intended to be displayed on the end user&#39;s device (required)
     * @param authReqId Authentication request id (optional)
     * @param loginHint A hint regarding the end-user for whom the authentications is being requested i.e email or phone (optional)
     * @param requestedExpiry Positive integer used to request the &#39;expires_in&#39; value (optional)
     * @param clientNotificationToken Client notification token (optional)
     * @param clientId The client id (optional)
     * @param clientAssertion The value of the client token (optional)
     * @param clientAssertionType  (optional)
     * @param created Created date. Measured in seconds since the Unix epoch (optional)
     * @param expired Expired date. Measured in seconds since the Unix epoch (optional)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call initiateAuthenticationRequestCall(String scope, String bindingMessage, String authReqId, String loginHint, Integer requestedExpiry, String clientNotificationToken, String clientId, String clientAssertion, ClientAssertionTypeModel clientAssertionType, Long created, Long expired, final ApiCallback _callback) throws ApiException {
        String basePath = null;

        // Operation Servers
        String[] localBasePaths = new String[] {  };

        // Determine Base Path to Use
        if (localCustomBaseUrl != null){
            basePath = localCustomBaseUrl;
        } else if ( localBasePaths.length > 0 ) {
            basePath = localBasePaths[localHostIndex];
        } else {
            basePath = null;
        }

        Object localVarPostBody = null;

        // create path and map variables
        String localVarPath = "/v1/auth/authorize";

        List<Pair> localVarQueryParams = new ArrayList<Pair>();
        List<Pair> localVarCollectionQueryParams = new ArrayList<Pair>();
        Map<String, String> localVarHeaderParams = new HashMap<String, String>();
        Map<String, String> localVarCookieParams = new HashMap<String, String>();
        Map<String, Object> localVarFormParams = new HashMap<String, Object>();

        if (authReqId != null) {
            localVarFormParams.put("auth_req_id", authReqId);
        }

        if (scope != null) {
            localVarFormParams.put("scope", scope);
        }

        if (loginHint != null) {
            localVarFormParams.put("login_hint", loginHint);
        }

        if (bindingMessage != null) {
            localVarFormParams.put("binding_message", bindingMessage);
        }

        if (requestedExpiry != null) {
            localVarFormParams.put("requested_expiry", requestedExpiry);
        }

        if (clientNotificationToken != null) {
            localVarFormParams.put("client_notification_token", clientNotificationToken);
        }

        if (clientId != null) {
            localVarFormParams.put("client_id", clientId);
        }

        if (clientAssertion != null) {
            localVarFormParams.put("client_assertion", clientAssertion);
        }

        if (clientAssertionType != null) {
            localVarFormParams.put("client_assertion_type", clientAssertionType);
        }

        if (created != null) {
            localVarFormParams.put("created", created);
        }

        if (expired != null) {
            localVarFormParams.put("expired", expired);
        }

        final String[] localVarAccepts = {
            "application/json"
        };
        final String localVarAccept = localVarApiClient.selectHeaderAccept(localVarAccepts);
        if (localVarAccept != null) {
            localVarHeaderParams.put("Accept", localVarAccept);
        }

        final String[] localVarContentTypes = {
            "application/x-www-form-urlencoded"
        };
        final String localVarContentType = localVarApiClient.selectHeaderContentType(localVarContentTypes);
        if (localVarHeaderParams != null) {
            localVarHeaderParams.put("Content-Type", localVarContentType);
        }

        String[] localVarAuthNames = new String[] { "bearer" };
        return localVarApiClient.buildCall(basePath, localVarPath, "POST", localVarQueryParams, localVarCollectionQueryParams, localVarPostBody, localVarHeaderParams, localVarCookieParams, localVarFormParams, localVarAuthNames, _callback);
    }

    @SuppressWarnings("rawtypes")
    private okhttp3.Call initiateAuthenticationRequestValidateBeforeCall(String scope, String bindingMessage, String authReqId, String loginHint, Integer requestedExpiry, String clientNotificationToken, String clientId, String clientAssertion, ClientAssertionTypeModel clientAssertionType, Long created, Long expired, final ApiCallback _callback) throws ApiException {
        
        // verify the required parameter 'scope' is set
        if (scope == null) {
            throw new ApiException("Missing the required parameter 'scope' when calling initiateAuthenticationRequest(Async)");
        }
        
        // verify the required parameter 'bindingMessage' is set
        if (bindingMessage == null) {
            throw new ApiException("Missing the required parameter 'bindingMessage' when calling initiateAuthenticationRequest(Async)");
        }
        

        okhttp3.Call localVarCall = initiateAuthenticationRequestCall(scope, bindingMessage, authReqId, loginHint, requestedExpiry, clientNotificationToken, clientId, clientAssertion, clientAssertionType, created, expired, _callback);
        return localVarCall;

    }

    /**
     * Initiate Authentication Request
     * Initiate Authentication Request
     * @param scope The scope of the access request (required)
     * @param bindingMessage Message intended to be displayed on the end user&#39;s device (required)
     * @param authReqId Authentication request id (optional)
     * @param loginHint A hint regarding the end-user for whom the authentications is being requested i.e email or phone (optional)
     * @param requestedExpiry Positive integer used to request the &#39;expires_in&#39; value (optional)
     * @param clientNotificationToken Client notification token (optional)
     * @param clientId The client id (optional)
     * @param clientAssertion The value of the client token (optional)
     * @param clientAssertionType  (optional)
     * @param created Created date. Measured in seconds since the Unix epoch (optional)
     * @param expired Expired date. Measured in seconds since the Unix epoch (optional)
     * @return AuthenticationResponseModel
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public AuthenticationResponseModel initiateAuthenticationRequest(String scope, String bindingMessage, String authReqId, String loginHint, Integer requestedExpiry, String clientNotificationToken, String clientId, String clientAssertion, ClientAssertionTypeModel clientAssertionType, Long created, Long expired) throws ApiException {
        ApiResponse<AuthenticationResponseModel> localVarResp = initiateAuthenticationRequestWithHttpInfo(scope, bindingMessage, authReqId, loginHint, requestedExpiry, clientNotificationToken, clientId, clientAssertion, clientAssertionType, created, expired);
        return localVarResp.getData();
    }

    /**
     * Initiate Authentication Request
     * Initiate Authentication Request
     * @param scope The scope of the access request (required)
     * @param bindingMessage Message intended to be displayed on the end user&#39;s device (required)
     * @param authReqId Authentication request id (optional)
     * @param loginHint A hint regarding the end-user for whom the authentications is being requested i.e email or phone (optional)
     * @param requestedExpiry Positive integer used to request the &#39;expires_in&#39; value (optional)
     * @param clientNotificationToken Client notification token (optional)
     * @param clientId The client id (optional)
     * @param clientAssertion The value of the client token (optional)
     * @param clientAssertionType  (optional)
     * @param created Created date. Measured in seconds since the Unix epoch (optional)
     * @param expired Expired date. Measured in seconds since the Unix epoch (optional)
     * @return ApiResponse&lt;AuthenticationResponseModel&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<AuthenticationResponseModel> initiateAuthenticationRequestWithHttpInfo(String scope, String bindingMessage, String authReqId, String loginHint, Integer requestedExpiry, String clientNotificationToken, String clientId, String clientAssertion, ClientAssertionTypeModel clientAssertionType, Long created, Long expired) throws ApiException {
        okhttp3.Call localVarCall = initiateAuthenticationRequestValidateBeforeCall(scope, bindingMessage, authReqId, loginHint, requestedExpiry, clientNotificationToken, clientId, clientAssertion, clientAssertionType, created, expired, null);
        Type localVarReturnType = new TypeToken<AuthenticationResponseModel>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * Initiate Authentication Request (asynchronously)
     * Initiate Authentication Request
     * @param scope The scope of the access request (required)
     * @param bindingMessage Message intended to be displayed on the end user&#39;s device (required)
     * @param authReqId Authentication request id (optional)
     * @param loginHint A hint regarding the end-user for whom the authentications is being requested i.e email or phone (optional)
     * @param requestedExpiry Positive integer used to request the &#39;expires_in&#39; value (optional)
     * @param clientNotificationToken Client notification token (optional)
     * @param clientId The client id (optional)
     * @param clientAssertion The value of the client token (optional)
     * @param clientAssertionType  (optional)
     * @param created Created date. Measured in seconds since the Unix epoch (optional)
     * @param expired Expired date. Measured in seconds since the Unix epoch (optional)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call initiateAuthenticationRequestAsync(String scope, String bindingMessage, String authReqId, String loginHint, Integer requestedExpiry, String clientNotificationToken, String clientId, String clientAssertion, ClientAssertionTypeModel clientAssertionType, Long created, Long expired, final ApiCallback<AuthenticationResponseModel> _callback) throws ApiException {

        okhttp3.Call localVarCall = initiateAuthenticationRequestValidateBeforeCall(scope, bindingMessage, authReqId, loginHint, requestedExpiry, clientNotificationToken, clientId, clientAssertion, clientAssertionType, created, expired, _callback);
        Type localVarReturnType = new TypeToken<AuthenticationResponseModel>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
    /**
     * Build call for initiateTokenRequest
     * @param grantType Grant type (required)
     * @param authReqId Unique id to identify the authentications request (optional)
     * @param scope The scope of the access request (optional)
     * @param clientId The client id (optional)
     * @param clientAssertion The value of the client token (optional)
     * @param clientAssertionType  (optional)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call initiateTokenRequestCall(String grantType, String authReqId, String scope, String clientId, String clientAssertion, ClientAssertionTypeModel clientAssertionType, final ApiCallback _callback) throws ApiException {
        String basePath = null;

        // Operation Servers
        String[] localBasePaths = new String[] {  };

        // Determine Base Path to Use
        if (localCustomBaseUrl != null){
            basePath = localCustomBaseUrl;
        } else if ( localBasePaths.length > 0 ) {
            basePath = localBasePaths[localHostIndex];
        } else {
            basePath = null;
        }

        Object localVarPostBody = null;

        // create path and map variables
        String localVarPath = "/v1/auth/token";

        List<Pair> localVarQueryParams = new ArrayList<Pair>();
        List<Pair> localVarCollectionQueryParams = new ArrayList<Pair>();
        Map<String, String> localVarHeaderParams = new HashMap<String, String>();
        Map<String, String> localVarCookieParams = new HashMap<String, String>();
        Map<String, Object> localVarFormParams = new HashMap<String, Object>();

        if (grantType != null) {
            localVarFormParams.put("grant_type", grantType);
        }

        if (authReqId != null) {
            localVarFormParams.put("auth_req_id", authReqId);
        }

        if (scope != null) {
            localVarFormParams.put("scope", scope);
        }

        if (clientId != null) {
            localVarFormParams.put("client_id", clientId);
        }

        if (clientAssertion != null) {
            localVarFormParams.put("client_assertion", clientAssertion);
        }

        if (clientAssertionType != null) {
            localVarFormParams.put("client_assertion_type", clientAssertionType);
        }

        final String[] localVarAccepts = {
            "application/json"
        };
        final String localVarAccept = localVarApiClient.selectHeaderAccept(localVarAccepts);
        if (localVarAccept != null) {
            localVarHeaderParams.put("Accept", localVarAccept);
        }

        final String[] localVarContentTypes = {
            "application/x-www-form-urlencoded"
        };
        final String localVarContentType = localVarApiClient.selectHeaderContentType(localVarContentTypes);
        if (localVarHeaderParams != null) {
            localVarHeaderParams.put("Content-Type", localVarContentType);
        }

        String[] localVarAuthNames = new String[] { "bearer" };
        return localVarApiClient.buildCall(basePath, localVarPath, "POST", localVarQueryParams, localVarCollectionQueryParams, localVarPostBody, localVarHeaderParams, localVarCookieParams, localVarFormParams, localVarAuthNames, _callback);
    }

    @SuppressWarnings("rawtypes")
    private okhttp3.Call initiateTokenRequestValidateBeforeCall(String grantType, String authReqId, String scope, String clientId, String clientAssertion, ClientAssertionTypeModel clientAssertionType, final ApiCallback _callback) throws ApiException {
        
        // verify the required parameter 'grantType' is set
        if (grantType == null) {
            throw new ApiException("Missing the required parameter 'grantType' when calling initiateTokenRequest(Async)");
        }
        

        okhttp3.Call localVarCall = initiateTokenRequestCall(grantType, authReqId, scope, clientId, clientAssertion, clientAssertionType, _callback);
        return localVarCall;

    }

    /**
     * Initiate Token Request
     * Initiate Token Request
     * @param grantType Grant type (required)
     * @param authReqId Unique id to identify the authentications request (optional)
     * @param scope The scope of the access request (optional)
     * @param clientId The client id (optional)
     * @param clientAssertion The value of the client token (optional)
     * @param clientAssertionType  (optional)
     * @return TokenResponseModel
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public TokenResponseModel initiateTokenRequest(String grantType, String authReqId, String scope, String clientId, String clientAssertion, ClientAssertionTypeModel clientAssertionType) throws ApiException {
        ApiResponse<TokenResponseModel> localVarResp = initiateTokenRequestWithHttpInfo(grantType, authReqId, scope, clientId, clientAssertion, clientAssertionType);
        return localVarResp.getData();
    }

    /**
     * Initiate Token Request
     * Initiate Token Request
     * @param grantType Grant type (required)
     * @param authReqId Unique id to identify the authentications request (optional)
     * @param scope The scope of the access request (optional)
     * @param clientId The client id (optional)
     * @param clientAssertion The value of the client token (optional)
     * @param clientAssertionType  (optional)
     * @return ApiResponse&lt;TokenResponseModel&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<TokenResponseModel> initiateTokenRequestWithHttpInfo(String grantType, String authReqId, String scope, String clientId, String clientAssertion, ClientAssertionTypeModel clientAssertionType) throws ApiException {
        okhttp3.Call localVarCall = initiateTokenRequestValidateBeforeCall(grantType, authReqId, scope, clientId, clientAssertion, clientAssertionType, null);
        Type localVarReturnType = new TypeToken<TokenResponseModel>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * Initiate Token Request (asynchronously)
     * Initiate Token Request
     * @param grantType Grant type (required)
     * @param authReqId Unique id to identify the authentications request (optional)
     * @param scope The scope of the access request (optional)
     * @param clientId The client id (optional)
     * @param clientAssertion The value of the client token (optional)
     * @param clientAssertionType  (optional)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> OK </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 403 </td><td> Forbidden </td><td>  -  </td></tr>
        <tr><td> 500 </td><td> Server Error </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call initiateTokenRequestAsync(String grantType, String authReqId, String scope, String clientId, String clientAssertion, ClientAssertionTypeModel clientAssertionType, final ApiCallback<TokenResponseModel> _callback) throws ApiException {

        okhttp3.Call localVarCall = initiateTokenRequestValidateBeforeCall(grantType, authReqId, scope, clientId, clientAssertion, clientAssertionType, _callback);
        Type localVarReturnType = new TypeToken<TokenResponseModel>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
}
