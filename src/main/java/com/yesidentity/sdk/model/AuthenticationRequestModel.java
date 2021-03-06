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


package com.yesidentity.sdk.model;

import java.util.Objects;
import java.util.Arrays;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.yesidentity.sdk.model.ClientAssertionTypeModel;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;

/**
 * AuthenticationRequestModel
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2022-01-01T07:44:54.268733600+01:00[Europe/Stockholm]")
public class AuthenticationRequestModel {
  public static final String SERIALIZED_NAME_AUTH_REQ_ID = "auth_req_id";
  @SerializedName(SERIALIZED_NAME_AUTH_REQ_ID)
  private String authReqId;

  public static final String SERIALIZED_NAME_SCOPE = "scope";
  @SerializedName(SERIALIZED_NAME_SCOPE)
  private String scope;

  public static final String SERIALIZED_NAME_LOGIN_HINT = "login_hint";
  @SerializedName(SERIALIZED_NAME_LOGIN_HINT)
  private String loginHint;

  public static final String SERIALIZED_NAME_BINDING_MESSAGE = "binding_message";
  @SerializedName(SERIALIZED_NAME_BINDING_MESSAGE)
  private String bindingMessage;

  public static final String SERIALIZED_NAME_REQUESTED_EXPIRY = "requested_expiry";
  @SerializedName(SERIALIZED_NAME_REQUESTED_EXPIRY)
  private Integer requestedExpiry;

  public static final String SERIALIZED_NAME_CLIENT_NOTIFICATION_TOKEN = "client_notification_token";
  @SerializedName(SERIALIZED_NAME_CLIENT_NOTIFICATION_TOKEN)
  private String clientNotificationToken;

  public static final String SERIALIZED_NAME_CLIENT_ID = "client_id";
  @SerializedName(SERIALIZED_NAME_CLIENT_ID)
  private String clientId;

  public static final String SERIALIZED_NAME_CLIENT_ASSERTION = "client_assertion";
  @SerializedName(SERIALIZED_NAME_CLIENT_ASSERTION)
  private String clientAssertion;

  public static final String SERIALIZED_NAME_CLIENT_ASSERTION_TYPE = "client_assertion_type";
  @SerializedName(SERIALIZED_NAME_CLIENT_ASSERTION_TYPE)
  private ClientAssertionTypeModel clientAssertionType;

  public static final String SERIALIZED_NAME_CREATED = "created";
  @SerializedName(SERIALIZED_NAME_CREATED)
  private Long created;

  public static final String SERIALIZED_NAME_EXPIRED = "expired";
  @SerializedName(SERIALIZED_NAME_EXPIRED)
  private Long expired;

  public AuthenticationRequestModel() { 
  }

  
  public AuthenticationRequestModel(
     String authReqId, 
     Long created, 
     Long expired
  ) {
    this();
    this.authReqId = authReqId;
    this.created = created;
    this.expired = expired;
  }

   /**
   * Authentication request id
   * @return authReqId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Authentication request id")

  public String getAuthReqId() {
    return authReqId;
  }




  public AuthenticationRequestModel scope(String scope) {
    
    this.scope = scope;
    return this;
  }

   /**
   * The scope of the access request
   * @return scope
  **/
  @javax.annotation.Nonnull
  @ApiModelProperty(required = true, value = "The scope of the access request")

  public String getScope() {
    return scope;
  }


  public void setScope(String scope) {
    this.scope = scope;
  }


  public AuthenticationRequestModel loginHint(String loginHint) {
    
    this.loginHint = loginHint;
    return this;
  }

   /**
   * A hint regarding the end-user for whom the authentications is being requested i.e email or phone
   * @return loginHint
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A hint regarding the end-user for whom the authentications is being requested i.e email or phone")

  public String getLoginHint() {
    return loginHint;
  }


  public void setLoginHint(String loginHint) {
    this.loginHint = loginHint;
  }


  public AuthenticationRequestModel bindingMessage(String bindingMessage) {
    
    this.bindingMessage = bindingMessage;
    return this;
  }

   /**
   * Message intended to be displayed on the end user&#39;s device
   * @return bindingMessage
  **/
  @javax.annotation.Nonnull
  @ApiModelProperty(required = true, value = "Message intended to be displayed on the end user's device")

  public String getBindingMessage() {
    return bindingMessage;
  }


  public void setBindingMessage(String bindingMessage) {
    this.bindingMessage = bindingMessage;
  }


  public AuthenticationRequestModel requestedExpiry(Integer requestedExpiry) {
    
    this.requestedExpiry = requestedExpiry;
    return this;
  }

   /**
   * Positive integer used to request the &#39;expires_in&#39; value
   * @return requestedExpiry
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Positive integer used to request the 'expires_in' value")

  public Integer getRequestedExpiry() {
    return requestedExpiry;
  }


  public void setRequestedExpiry(Integer requestedExpiry) {
    this.requestedExpiry = requestedExpiry;
  }


  public AuthenticationRequestModel clientNotificationToken(String clientNotificationToken) {
    
    this.clientNotificationToken = clientNotificationToken;
    return this;
  }

   /**
   * Client notification token
   * @return clientNotificationToken
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Client notification token")

  public String getClientNotificationToken() {
    return clientNotificationToken;
  }


  public void setClientNotificationToken(String clientNotificationToken) {
    this.clientNotificationToken = clientNotificationToken;
  }


  public AuthenticationRequestModel clientId(String clientId) {
    
    this.clientId = clientId;
    return this;
  }

   /**
   * The client id
   * @return clientId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The client id")

  public String getClientId() {
    return clientId;
  }


  public void setClientId(String clientId) {
    this.clientId = clientId;
  }


  public AuthenticationRequestModel clientAssertion(String clientAssertion) {
    
    this.clientAssertion = clientAssertion;
    return this;
  }

   /**
   * The value of the client token
   * @return clientAssertion
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The value of the client token")

  public String getClientAssertion() {
    return clientAssertion;
  }


  public void setClientAssertion(String clientAssertion) {
    this.clientAssertion = clientAssertion;
  }


  public AuthenticationRequestModel clientAssertionType(ClientAssertionTypeModel clientAssertionType) {
    
    this.clientAssertionType = clientAssertionType;
    return this;
  }

   /**
   * Get clientAssertionType
   * @return clientAssertionType
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public ClientAssertionTypeModel getClientAssertionType() {
    return clientAssertionType;
  }


  public void setClientAssertionType(ClientAssertionTypeModel clientAssertionType) {
    this.clientAssertionType = clientAssertionType;
  }


   /**
   * Created date. Measured in seconds since the Unix epoch
   * @return created
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Created date. Measured in seconds since the Unix epoch")

  public Long getCreated() {
    return created;
  }




   /**
   * Expired date. Measured in seconds since the Unix epoch
   * @return expired
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Expired date. Measured in seconds since the Unix epoch")

  public Long getExpired() {
    return expired;
  }




  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AuthenticationRequestModel authenticationRequest = (AuthenticationRequestModel) o;
    return Objects.equals(this.authReqId, authenticationRequest.authReqId) &&
        Objects.equals(this.scope, authenticationRequest.scope) &&
        Objects.equals(this.loginHint, authenticationRequest.loginHint) &&
        Objects.equals(this.bindingMessage, authenticationRequest.bindingMessage) &&
        Objects.equals(this.requestedExpiry, authenticationRequest.requestedExpiry) &&
        Objects.equals(this.clientNotificationToken, authenticationRequest.clientNotificationToken) &&
        Objects.equals(this.clientId, authenticationRequest.clientId) &&
        Objects.equals(this.clientAssertion, authenticationRequest.clientAssertion) &&
        Objects.equals(this.clientAssertionType, authenticationRequest.clientAssertionType) &&
        Objects.equals(this.created, authenticationRequest.created) &&
        Objects.equals(this.expired, authenticationRequest.expired);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authReqId, scope, loginHint, bindingMessage, requestedExpiry, clientNotificationToken, clientId, clientAssertion, clientAssertionType, created, expired);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AuthenticationRequestModel {\n");
    sb.append("    authReqId: ").append(toIndentedString(authReqId)).append("\n");
    sb.append("    scope: ").append(toIndentedString(scope)).append("\n");
    sb.append("    loginHint: ").append(toIndentedString(loginHint)).append("\n");
    sb.append("    bindingMessage: ").append(toIndentedString(bindingMessage)).append("\n");
    sb.append("    requestedExpiry: ").append(toIndentedString(requestedExpiry)).append("\n");
    sb.append("    clientNotificationToken: ").append(toIndentedString(clientNotificationToken)).append("\n");
    sb.append("    clientId: ").append(toIndentedString(clientId)).append("\n");
    sb.append("    clientAssertion: ").append(toIndentedString(clientAssertion)).append("\n");
    sb.append("    clientAssertionType: ").append(toIndentedString(clientAssertionType)).append("\n");
    sb.append("    created: ").append(toIndentedString(created)).append("\n");
    sb.append("    expired: ").append(toIndentedString(expired)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

}

