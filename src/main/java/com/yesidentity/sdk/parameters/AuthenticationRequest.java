package com.yesidentity.sdk.parameters;

import com.yesidentity.sdk.model.OpenIDConfigurationModel;

public class AuthenticationRequest {

    private final OpenIDConfigurationModel.ScopesSupportedEnum scope;
    private final String bindingMessage;

    private String loginHint;
    private Integer requestedExpiry;
    private String clientNotificationToken;

    public AuthenticationRequest(OpenIDConfigurationModel.ScopesSupportedEnum scope, String bindingMessage) {
        this.scope = scope;
        this.bindingMessage = bindingMessage;
    }

    public OpenIDConfigurationModel.ScopesSupportedEnum getScope() {
        return scope;
    }

    public String getBindingMessage() {
        return bindingMessage;
    }

    public String getLoginHint() {
        return loginHint;
    }

    public Integer getRequestedExpiry() {
        return requestedExpiry;
    }

    public String getClientNotificationToken() {
        return clientNotificationToken;
    }

    public AuthenticationRequest loginHint(String loginHint) {
        this.loginHint = loginHint;
        return this;
    }

    public AuthenticationRequest requestedExpiry(Integer requestedExpiry) {
        this.requestedExpiry = requestedExpiry;
        return this;
    }

    public AuthenticationRequest clientNotificationToken(String clientNotificationToken) {
        this.clientNotificationToken = clientNotificationToken;
        return this;
    }
}
