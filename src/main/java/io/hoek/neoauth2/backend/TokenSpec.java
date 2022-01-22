package io.hoek.neoauth2.backend;

import com.google.common.collect.Streams;
import io.hoek.neoauth2.internal.InvalidRequestException;
import io.hoek.neoauth2.model.ErrorResponse;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class TokenSpec {
    // FIXME FIXME How to make final?

    private String clientId;
    private List<String> scopes;
    private Map<String, String> claims;

    @SuppressWarnings("unchecked")
    public static TokenSpec from(ClientRegistration client, UserRegistration user, String clientId, List<String> scopes, String nonce) throws InvalidRequestException {
        String aud = client.validateScopesAndGetAudience(scopes);
        if (aud == null) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_SCOPE, "scopes not authorized");
        }

        return new TokenSpec(clientId, scopes,
                Map.ofEntries(
                        Streams.concat(
                                Stream.of(
                                        Map.entry("aud", aud),
                                        Map.entry("sub", user.getSub())),
                                // SPEC NOTE: Nonstandard OIDC extension
                                nonce == null
                                        ? Stream.of() : Stream.of(Map.entry("nonce", nonce)),
                                // Custom claims:
                                user.getGroups().isEmpty()
                                        ? Stream.of() : Stream.of("groups", String.join(" ", user.getGroups())),
                                user.getCustomClaims().isEmpty()
                                        ? Stream.of() : user.getCustomClaims().entrySet().stream()
                        ).toArray(Map.Entry[]::new)));
    }
}
