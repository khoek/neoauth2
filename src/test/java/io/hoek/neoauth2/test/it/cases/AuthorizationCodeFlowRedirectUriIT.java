package io.hoek.neoauth2.test.it.cases;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.hoek.neoauth2.backend.ClientRegistration;
import io.hoek.neoauth2.model.ErrorResponse;
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

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AuthorizationCodeFlowRedirectUriIT {

    @Test
    public void testAuthorizationCodeFlowRedirectUriWrongAtTokenEndpoint() throws IOException {
        ErrorResponse er = Flows.assertAuthorizationCodeFlowFailsAtTokenEndpoint(redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {
            private static final String BAD_REDIRECT_URI = "https://agentborris.com/legendary";

            @Override
            public ClientRegistration getClientRegistration() {
                return new MockCredentials.MockClientRegistration() {
                    @Override
                    public @NonNull Collection<URI> getAllowedRedirectUris() {
                        return List.of(redirectUri, URI.create(BAD_REDIRECT_URI));
                    }
                };
            }

            @Override
            protected Collection<Param> getTokenEndpointParams(String code) {
                return Set.of(new Param("grant_type", "authorization_code"),
                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                        new Param("redirect_uri", BAD_REDIRECT_URI),
                        new Param("code", code),
                        new Param("code_verifier", getCodeVerifier()));
            }
        });

        assertEquals(new ErrorResponse("invalid_grant", "mismatched 'redirect_uri' with authorization code", null), er);
    }

    @Test
    public void testAuthorizationCodeFlowRedirectUriMalformedAtTokenEndpoint() throws IOException {
        ErrorResponse er = Flows.assertAuthorizationCodeFlowFailsAtTokenEndpoint(redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {
            @Override
            protected Collection<Param> getTokenEndpointParams(String code) {
                return Set.of(new Param("grant_type", "authorization_code"),
                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                        new Param("redirect_uri", "?||/???OMGLOL!!!"),
                        new Param("code", code),
                        new Param("code_verifier", getCodeVerifier()));
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "malformed 'redirect_uri'", null), er);
    }

    @Test
    public void testAuthorizationCodeFlowRedirectUriWrongAtTokenEndpointUsingDefault() throws IOException {
        ErrorResponse er = Flows.assertAuthorizationCodeFlowFailsAtTokenEndpoint(redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {
            @Override
            public ClientRegistration getClientRegistration() {
                return new MockCredentials.MockClientRegistration() {
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
                        new Param("redirect_uri", "https://agentborris.com/legendary"),
                        new Param("code", code),
                        new Param("code_verifier", getCodeVerifier()));
            }
        });

        assertEquals(new ErrorResponse("invalid_grant", "'redirect_uri' does not match registered default", null), er);
    }

    @Test
    public void testAuthorizationCodeFlowRedirectUriSuccessUsingDefaultButExplicitAtToken() throws IOException {
        ObjectNode response = Flows.assertAuthorizationCodeFlowSucceeds(redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {
            @Override
            public ClientRegistration getClientRegistration() {
                return new MockCredentials.MockClientRegistration() {
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
        });

        MockCredentials.assertAccessTokenClaimsValidForDefaultIssuer(response);
    }

    @Test
    public void testAuthorizationCodeFlowRedirectUriMissingAtToken() throws IOException {
        ErrorResponse er = Flows.assertAuthorizationCodeFlowFailsAtTokenEndpoint(redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {
            @Override
            protected Collection<Param> getTokenEndpointParams(String code) {
                return Set.of(new Param("grant_type", "authorization_code"),
                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                        new Param("code", code),
                        new Param("code_verifier", getCodeVerifier()));
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "missing 'redirect_uri'", null), er);
    }

    @Test
    public void testAuthorizationCodeFlowRedirectUriMissingAtTokenEvenThoughIsDefault() throws IOException {
        ErrorResponse er = Flows.assertAuthorizationCodeFlowFailsAtTokenEndpoint(redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {
            @Override
            public ClientRegistration getClientRegistration() {
                return new MockCredentials.MockClientRegistration() {
                    @Override
                    public @NonNull Collection<URI> getAllowedRedirectUris() {
                        return List.of(redirectUri);
                    }
                };
            }

            @Override
            protected Collection<Param> getTokenEndpointParams(String code) {
                return Set.of(new Param("grant_type", "authorization_code"),
                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                        new Param("code", code),
                        new Param("code_verifier", getCodeVerifier()));
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "missing 'redirect_uri'", null), er);
    }

    @Test
    public void testAuthorizationCodeFlowRedirectUriSuccessOmittedAtTokenButUsingDefault() throws IOException {
        ObjectNode response = Flows.assertAuthorizationCodeFlowSucceeds(redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {
            @Override
            public ClientRegistration getClientRegistration() {
                return new MockCredentials.MockClientRegistration() {
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
}
