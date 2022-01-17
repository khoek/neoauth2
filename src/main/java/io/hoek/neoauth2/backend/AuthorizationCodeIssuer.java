package io.hoek.neoauth2.backend;

import io.hoek.neoauth2.model.AuthorizationCodePayload;

import javax.validation.constraints.NotNull;
import java.time.Instant;

public interface AuthorizationCodeIssuer {

    // SPEC NOTE: Expiry should be less than 10 min.
    @NotNull AuthorizationCodePayload issueAuthorizationCode(AuthorizationCodeOrder order, Instant expiry);

    // Returns `null` if the code is invalid.
    AuthorizationCodeOrder readAndVerifyAuthorizationCode(AuthorizationCodePayload payload);
}
