package io.hoek.neoauth2.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum GrantType {

    // FIXME What else does OAuth2.1 allow?

    @JsonProperty("authorization_code")
    AUTHORIZATION_CODE,
}
