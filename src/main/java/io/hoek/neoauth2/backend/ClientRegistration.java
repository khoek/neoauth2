package io.hoek.neoauth2.backend;

import javax.validation.constraints.NotNull;
import java.net.URI;
import java.util.Collection;
import java.util.List;

public interface ClientRegistration {

    default List<String> getDefaultScopes() {
        return null;
    }

    @NotNull

    Collection<URI> getAllowedRedirectUris();

    // Returns null if validation of the scopes fails.
    String validateScopesAndGetAudience(@NotNull List<String> scopes);

    // SPEC NOTE: Expiry should be less than 10 min.
    default @NotNull String getClientSecret() {
        return null;
    }

    // SPEC NOTE: Expiry should be less than 10 min.
    default long getAuthorizationCodeLifetimeSeconds() {
        return 60L;
    }

    long getAccessTokenLifetimeSeconds();
}
