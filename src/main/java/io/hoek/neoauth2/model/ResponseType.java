package io.hoek.neoauth2.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.hoek.neoauth2.internal.ParamWriter;
import io.hoek.neoauth2.internal.UriFragmentParamWriter;
import io.hoek.neoauth2.internal.UriQueryParamWriter;

import java.net.URI;

public enum ResponseType {

    @JsonProperty("code")
    AUTHORIZATION_CODE,

    // Not allowed by OAuth 2.1, support must be explicitly enabled using `BackwardsCompat`.
    @JsonProperty("token")
    IMPLICIT,
    ;

    // We don't allow the "hybrid" flow.

    public ParamWriter<URI> getWriter(URI redirectUri) {
        switch (this) {
            case AUTHORIZATION_CODE:
                return new UriQueryParamWriter(redirectUri);
            case IMPLICIT:
                return new UriFragmentParamWriter(redirectUri);
            default:
                throw new UnsupportedOperationException();
        }
    }
}
