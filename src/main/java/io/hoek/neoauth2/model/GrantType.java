package io.hoek.neoauth2.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum GrantType {

    // TODO Implement client credentials

    @JsonProperty("authorization_code")
    AUTHORIZATION_CODE,
}
