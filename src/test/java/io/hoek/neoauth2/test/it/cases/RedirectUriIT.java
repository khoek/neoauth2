package io.hoek.neoauth2.test.it.cases;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.hoek.neoauth2.backend.RegistrationAuthority;
import io.hoek.neoauth2.test.MockCredentials;
import io.hoek.neoauth2.test.Param;
import io.hoek.neoauth2.test.it.Flows;
import io.hoek.neoauth2.test.it.MockFlows;
import lombok.NonNull;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.Set;

public class RedirectUriIT {

    @Test
    public void testRedirectUriSuccessUseDefault() throws IOException {
        ObjectNode response = Flows.assertAuthorizationCodeFlowSucceeds(
                redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {
                    @Override
                    public RegistrationAuthority getRegistrationAuthority() {
                        return clientId -> new MockCredentials.MockClientInfo() {
                            @Override
                            public @NonNull Collection<URI> getAllowedRedirectUris() {
                                return List.of(redirectUri);
                            }
                        };
                    }

                    @Override
                    public Collection<Param> getAuthorizationEndpointParams() {
                        return Set.of(new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", getCodeChallenge()));
                    }

                    @Override
                    protected Collection<Param> getTokenEndpointParams(String code) {
                        return Set.of(new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("code", code),
                                new Param("code_verifier", getCodeVerifier()));
                    }
                });

        MockCredentials.assertAccessTokenClaimsValidForDefaultIssuer(response);
    }

    @Test
    public void testRedirectUriSuccessUseDefaultExplicitAtToken() throws IOException {
        ObjectNode response = Flows.assertAuthorizationCodeFlowSucceeds(
                redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {
                    @Override
                    public RegistrationAuthority getRegistrationAuthority() {
                        return clientId -> new MockCredentials.MockClientInfo() {
                            @Override
                            public @NonNull Collection<URI> getAllowedRedirectUris() {
                                return List.of(redirectUri);
                            }
                        };
                    }

                    @Override
                    public Collection<Param> getAuthorizationEndpointParams() {
                        return Set.of(new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", getCodeChallenge()));
                    }

                    @Override
                    protected Collection<Param> getTokenEndpointParams(String code) {
                        return Set.of(new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", redirectUri.toString()),
                                new Param("code", code),
                                new Param("code_verifier", getCodeVerifier()));
                    }
                });

        MockCredentials.assertAccessTokenClaimsValidForDefaultIssuer(response);
    }
}
