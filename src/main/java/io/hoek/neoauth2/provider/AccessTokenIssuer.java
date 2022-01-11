package io.hoek.neoauth2.provider;

import io.hoek.neoauth2.model.AccessTokenPayload;

public interface AccessTokenIssuer {

    AccessTokenPayload issueAccessToken(AccessTokenOrder order);
}
