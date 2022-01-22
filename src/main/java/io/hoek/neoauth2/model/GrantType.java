package io.hoek.neoauth2.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum GrantType {

    @JsonProperty("authorization_code")
    AUTHORIZATION_CODE,

    @JsonProperty("client_credentials")
    CLIENT_CREDENTIALS,
}
