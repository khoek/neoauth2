package io.hoek.neoauth2.backend.builtin;

import io.hoek.neoauth2.backend.ClientRegistration;
import org.apache.commons.collections4.CollectionUtils;

import javax.validation.constraints.NotNull;
import java.util.List;
import java.util.Objects;

public abstract class SingleScopeClientRegistration implements ClientRegistration {

    private final String scope;

    public SingleScopeClientRegistration(String scope) {
        this.scope = Objects.requireNonNull(scope);
    }

    @Override
    public final List<String> getDefaultScopes() {
        return List.of(scope);
    }

    // Returns null if validation of the scopes fails.
    public final String validateScopesAndGetAudience(@NotNull List<String> scopes) {
        if(!CollectionUtils.isEqualCollection(scopes, List.of(scope))) {
            return null;
        }

        return scope;
    }
}
