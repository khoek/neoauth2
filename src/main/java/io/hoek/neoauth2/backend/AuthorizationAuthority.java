package io.hoek.neoauth2.backend;

import io.hoek.neoauth2.model.AuthorizationCodePayload;
import io.hoek.neoauth2.model.RefreshTokenPayload;

import javax.validation.constraints.NotNull;
import java.time.Instant;

public interface AuthorizationAuthority {

    // SPEC NOTE: Expiry should be less than 10 min.
    @NotNull AuthorizationCodePayload issueAuthorizationCode(UserAuthorization order, Instant expiry);

    // Returns `null` if the code is invalid.
    UserAuthorization readAndVerifyAuthorizationCode(AuthorizationCodePayload payload);

    UserAuthorization readAndVerifyRefreshToken(RefreshTokenPayload token);

    class Disabled implements AuthorizationAuthority {

        @Override
        public AuthorizationCodePayload issueAuthorizationCode(UserAuthorization order, Instant expiry) {
            throw new UnsupportedOperationException("issuance of authorization codes explicitly disabled");
        }

        @Override
        public UserAuthorization readAndVerifyAuthorizationCode(AuthorizationCodePayload payload) {
            throw new UnsupportedOperationException("verification of authorization codes explicitly disabled");
        }

        @Override
        public UserAuthorization readAndVerifyRefreshToken(RefreshTokenPayload payload) {
            throw new UnsupportedOperationException("verification of refresh tokens explicitly disabled");
        }
    }

}
