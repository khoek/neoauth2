package io.hoek.neoauth2.test.it.cases;

import io.hoek.neoauth2.backend.ClientRegistration;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.test.MockCredentials;
import io.hoek.neoauth2.test.Param;
import io.hoek.neoauth2.test.it.Flows;
import io.hoek.neoauth2.test.it.MockFlows;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AuthorizationCodeFlowBadCodeIT {

    // FIXME Doesn't really make sense as a token unit test, since the default scopes have already been substituted if so
    @Test
    public void testMismatchedScopesUsingDefault() throws IOException {
        ErrorResponse er = Flows.assertAuthorizationCodeFlowFailsAtTokenEndpoint(redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {
            @Override
            protected Collection<Param> getTokenEndpointParams(String code) {
                return Set.of(new Param("grant_type", "authorization_code"),
                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                        new Param("scope", String.join(" ", List.of("31337Haxxor77scopeA", "31337Haxxor77scopeB"))),
                        new Param("redirect_uri", redirectUri.toString()),
                        new Param("code", code),
                        new Param("code_verifier", getCodeVerifier()));
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "mismatched 'scope' with authorization code", null), er);
    }

    @Test
    public void testSecondUseOfCode() throws IOException {
        ErrorResponse er = Flows.assertAuthorizationCodeFlowFailsAtTokenEndpoint(redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {
            @Override
            public Flows.TokenEndpointResponse completeFlow(Flows.TokenEndpoint endpoint, String code) {
                Flows.TokenEndpointResponse first = super.completeFlow(endpoint, code);
                MockCredentials.assertAccessTokenClaimsValidForDefaultIssuer(first.unwrapSuccess());

                return super.completeFlow(endpoint, code);
            }
        });

        assertEquals(new ErrorResponse("invalid_grant", "invalid code", null), er);
    }

    @Test
    public void testExpiredCode() throws IOException {
        ErrorResponse er = Flows.assertAuthorizationCodeFlowFailsAtTokenEndpoint(redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {
            @Override
            public ClientRegistration getClientRegistration() {
                return new MockCredentials.MockClientRegistration() {
                    @Override
                    public long getAuthorizationCodeLifetimeSeconds() {
                        return 0;
                    }
                };
            }

            @SneakyThrows
            @Override
            public Flows.TokenEndpointResponse completeFlow(Flows.TokenEndpoint endpoint, String code) {
                Thread.sleep(1000);
                return super.completeFlow(endpoint, code);
            }
        });

        assertEquals(new ErrorResponse("invalid_grant", "invalid code", null), er);
    }
}
