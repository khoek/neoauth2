package io.hoek.neoauth2.provider;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class AccessTokenOrder {

    private final String sub;
    private final String aud;
    private final List<String> scopes;
    private final long expiresInSeconds;
    private final String clientId;

    // SPEC NOTE: Nonstandard OIDC extension
    private final String nonce;
}
