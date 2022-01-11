package io.hoek.neoauth2.provider;

import io.hoek.neoauth2.model.AuthorizationCodePayload;

import java.time.Instant;

public interface AuthorizationCodeIssuer {

    // FIXME Where to check this
    // SPEC NOTE: Expiry should be less than 10 min.
    AuthorizationCodePayload issueAuthorizationCode(AuthorizationCodeOrder order, Instant expiry);

    AuthorizationCodeOrder readAndVerifyAuthorizationCode(AuthorizationCodePayload payload);
}
