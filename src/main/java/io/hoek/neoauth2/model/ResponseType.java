package io.hoek.neoauth2.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum ResponseType {

    @JsonProperty("code")
    AUTHORIZATION_CODE,

    // Not allowed by OAuth 2.1, support must be explicitly enabled using `BackwardsCompat`.
    @JsonProperty("token")
    IMPLICIT,

    // We don't allow the "hybrid" flow.
}
