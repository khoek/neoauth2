package io.hoek.neoauth2.backend;

import lombok.NonNull;

import java.net.URI;
import java.util.Collection;
import java.util.List;

public interface RegistrationAuthority {
    ClientInfo lookupClientId(String clientId);

    interface ClientInfo {
        default List<String> getDefaultScopes() {
            return null;
        }

        @NonNull
        Collection<URI> getAllowedRedirectUris();

        // Returns null if validation of the scopes fails.
        String validateScopesAndGetAudience(List<String> scopes);

        // SPEC NOTE: Expiry should be less than 10 min.
        long getAuthorizationCodeLifetimeSeconds();

        long getAccessTokenLifetimeSeconds();
    }
}
