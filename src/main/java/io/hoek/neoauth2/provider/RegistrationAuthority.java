package io.hoek.neoauth2.provider;

import lombok.NonNull;

import java.net.URI;
import java.util.Collection;
import java.util.List;

public interface RegistrationAuthority {
    ClientInfo lookupClientId(String clientId);

    interface ClientInfo {
        List<String> getDefaultScopes();

        @NonNull
        Collection<URI> getAllowedRedirectUris();

        @NonNull
        String validateScopesAndGetAudience(List<String> scopes);

        @NonNull
        long getAuthorizationCodeLifetimeSeconds();

        @NonNull
        long getAccessTokenLifetimeSeconds();
    }
}
