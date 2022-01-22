package io.hoek.neoauth2.backend;

import io.hoek.neoauth2.model.AccessTokenPayload;
import io.hoek.neoauth2.model.AuthorizationCodePayload;
import io.hoek.neoauth2.model.RefreshTokenPayload;

import java.time.Instant;

public final class IssuerBundle implements AuthorizationAuthority, AccessTokenIssuer {

    private final AuthorizationAuthority auth;
    private final AccessTokenIssuer access;

    private IssuerBundle(AuthorizationAuthority auth, AccessTokenIssuer access) {
        this.auth = auth;
        this.access = access;
    }

    public static IssuerBundle withoutAuthorization(AccessTokenIssuer access) {
        return IssuerBundle.with(new AuthorizationAuthority.Disabled(), access);
    }

    public static <Both extends AuthorizationAuthority & AccessTokenIssuer> IssuerBundle with(Both both) {
        return IssuerBundle.with(both, both);
    }

    public static IssuerBundle with(AuthorizationAuthority auth, AccessTokenIssuer access) {
        return new IssuerBundle(auth, access);
    }

    @Override
    public AuthorizationCodePayload issueAuthorizationCode(UserAuthorization order, Instant expiry) {
        return auth.issueAuthorizationCode(order, expiry);
    }

    @Override
    public UserAuthorization readAndVerifyAuthorizationCode(AuthorizationCodePayload payload) {
        return auth.readAndVerifyAuthorizationCode(payload);
    }

    @Override
    public UserAuthorization readAndVerifyRefreshToken(RefreshTokenPayload payload) {
        return auth.readAndVerifyRefreshToken(payload);
    }

    @Override
    public AccessTokenPayload issueAccessToken(AccessTokenOrder order) {
        return access.issueAccessToken(order);
    }
}
