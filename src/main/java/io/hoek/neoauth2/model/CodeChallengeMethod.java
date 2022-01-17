package io.hoek.neoauth2.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.hoek.neoauth2.internal.Util;

public enum CodeChallengeMethod {

    // Default according to the PKCE spec
    @JsonProperty("plain")
    PLAIN,
    // SHA-256
    @JsonProperty("S256")
    S256,
    ;

    public String calculateChallenge(String codeVerifier) {
        switch (this) {
            case PLAIN:
                return codeVerifier;
            case S256:
                return Util.calculateSha256Base64UrlEncodedWithoutPadding(codeVerifier);
            default:
                throw new UnsupportedOperationException();
        }
    }
}
