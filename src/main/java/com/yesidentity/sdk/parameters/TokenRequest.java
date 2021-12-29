package com.yesidentity.sdk.parameters;

import com.yesidentity.sdk.model.OpenIDConfigurationModel;

public class TokenRequest {

    private final OpenIDConfigurationModel.GrantTypesSupportedEnum grantType;
    private String authReqId;
    private String scope;

    public TokenRequest(OpenIDConfigurationModel.GrantTypesSupportedEnum grantType) {
        this.grantType = grantType;
    }

    public OpenIDConfigurationModel.GrantTypesSupportedEnum getGrantType() {
        return grantType;
    }

    public String getAuthReqId() {
        return authReqId;
    }

    public String getScope() {
        return scope;
    }

    public TokenRequest authReqId(String authReqId) {
        this.authReqId = authReqId;
        return this;
    }

    public TokenRequest scope(String scope) {
        this.scope = scope;
        return this;
    }
}
