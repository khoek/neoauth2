package io.hoek.neoauth2.provider;

import io.hoek.neoauth2.model.AccessTokenPayload;
import io.hoek.neoauth2.model.AuthorizationCodePayload;
import lombok.AllArgsConstructor;

import java.time.Instant;

@AllArgsConstructor
public final class IssuerBundle<Auth extends AuthorizationCodeIssuer, Access extends AccessTokenIssuer>
        implements AuthorizationCodeIssuer, AccessTokenIssuer {
    private final Auth authorizationCodeIssuer;
    private final Access accessTokenIssuer;

    @Override
    public AuthorizationCodePayload issueAuthorizationCode(AuthorizationCodeOrder order, Instant expiry) {
        return authorizationCodeIssuer.issueAuthorizationCode(order, expiry);
    }

    @Override
    public AuthorizationCodeOrder readAndVerifyAuthorizationCode(AuthorizationCodePayload payload) {
        return authorizationCodeIssuer.readAndVerifyAuthorizationCode(payload);
    }

    @Override
    public AccessTokenPayload issueAccessToken(AccessTokenOrder order) {
        return accessTokenIssuer.issueAccessToken(order);
    }
}
