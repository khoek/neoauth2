package io.hoek.neoauth2.test.it.cases;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.provider.RegistrationAuthority;
import io.hoek.neoauth2.test.it.FlowProfiles;
import io.hoek.neoauth2.test.it.FlowSimulator;
import io.hoek.neoauth2.test.it.MockCredentials;
import lombok.NonNull;
import org.junit.jupiter.api.Test;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AuthorizationCodeFlowRedirectUriIT {

    @Test
    public void testAuthorizationCodeFlowRedirectUriWrongAtTokenEndpoint() throws IOException {
        ErrorResponse er = FlowSimulator.assertFlowFailsAtTokenEndpoint(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri) {
            @Override
            public String buildEndpointParamsForToken(String code) {
                return "grant_type=authorization_code"
                        + "&client_id=" + URLEncoder.encode(MockCredentials.DEFAULT_CLAIM_CLIENT_ID, StandardCharsets.UTF_8)
                        + "&redirect_uri=" + URLEncoder.encode("https://agentborris.com/legendary", StandardCharsets.UTF_8)
                        + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                        + "&code_verifier=" + URLEncoder.encode(getCodeVerifier(), StandardCharsets.UTF_8);
            }
        });

        assertEquals(new ErrorResponse("invalid_grant", "mismatched 'redirect_uri' with authorization code", null), er);
    }

    @Test
    public void testAuthorizationCodeFlowRedirectUriMalformedAtTokenEndpoint() throws IOException {
        ErrorResponse er = FlowSimulator.assertFlowFailsAtTokenEndpoint(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri) {
            @Override
            public String buildEndpointParamsForToken(String code) {
                return "grant_type=authorization_code"
                        + "&client_id=" + URLEncoder.encode(MockCredentials.DEFAULT_CLAIM_CLIENT_ID, StandardCharsets.UTF_8)
                        + "&redirect_uri=" + URLEncoder.encode("?||/???OMGLOL!!!", StandardCharsets.UTF_8)
                        + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                        + "&code_verifier=" + URLEncoder.encode(getCodeVerifier(), StandardCharsets.UTF_8);
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "malformed 'redirect_uri'", null), er);
    }

    @Test
    public void testAuthorizationCodeFlowRedirectUriWrongAtTokenEndpointUsingDefault() throws IOException {
        ErrorResponse er = FlowSimulator.assertFlowFailsAtTokenEndpoint(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri) {
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
            public URI buildEndpointParamsForAuthorization(URI authorizationUri) {
                return UriBuilder.fromUri(authorizationUri).queryParam("response_type", "code")
                        .queryParam("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID)
                        .queryParam("code_challenge_method", "S256")
                        .queryParam("code_challenge", getCodeChallenge())
                        .build();
            }

            @Override
            public String buildEndpointParamsForToken(String code) {
                return "grant_type=authorization_code"
                        + "&client_id=" + URLEncoder.encode(MockCredentials.DEFAULT_CLAIM_CLIENT_ID, StandardCharsets.UTF_8)
                        + "&redirect_uri=" + URLEncoder.encode("https://agentborris.com/legendary", StandardCharsets.UTF_8)
                        + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                        + "&code_verifier=" + URLEncoder.encode(getCodeVerifier(), StandardCharsets.UTF_8);
            }
        });

        assertEquals(new ErrorResponse("invalid_grant", "'redirect_uri' does not match registered default", null), er);
    }

    @Test
    public void testAuthorizationCodeFlowRedirectUriSuccessUsingDefaultButExplicitAtToken() throws IOException {
        ObjectNode response = FlowSimulator.assertFlowSucceeds(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri) {
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
            public URI buildEndpointParamsForAuthorization(URI authorizationUri) {
                return UriBuilder.fromUri(authorizationUri).queryParam("response_type", "code")
                        .queryParam("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID)
                        .queryParam("code_challenge_method", "S256")
                        .queryParam("code_challenge", getCodeChallenge())
                        .build();
            }
        });

        FlowProfiles.assertAccessTokenValidClaims(response);
    }

    @Test
    public void testAuthorizationCodeFlowRedirectUriMissingAtToken() throws IOException {
        ErrorResponse er = FlowSimulator.assertFlowFailsAtTokenEndpoint(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri) {
            @Override
            public String buildEndpointParamsForToken(String code) {
                return "grant_type=authorization_code"
                        + "&client_id=" + URLEncoder.encode(MockCredentials.DEFAULT_CLAIM_CLIENT_ID, StandardCharsets.UTF_8)
                        + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                        + "&code_verifier=" + URLEncoder.encode(getCodeVerifier(), StandardCharsets.UTF_8);
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "missing 'redirect_uri'", null), er);
    }

    @Test
    public void testAuthorizationCodeFlowRedirectUriMissingAtTokenEvenThoughIsDefault() throws IOException {
        ErrorResponse er = FlowSimulator.assertFlowFailsAtTokenEndpoint(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri) {
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
            public String buildEndpointParamsForToken(String code) {
                return "grant_type=authorization_code"
                        + "&client_id=" + URLEncoder.encode(MockCredentials.DEFAULT_CLAIM_CLIENT_ID, StandardCharsets.UTF_8)
                        + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                        + "&code_verifier=" + URLEncoder.encode(getCodeVerifier(), StandardCharsets.UTF_8);
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "missing 'redirect_uri'", null), er);
    }

    @Test
    public void testAuthorizationCodeFlowRedirectUriSuccessOmittedAtTokenButUsingDefault() throws IOException {
        ObjectNode response = FlowSimulator.assertFlowSucceeds(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri) {
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
            public URI buildEndpointParamsForAuthorization(URI authorizationUri) {
                return UriBuilder.fromUri(authorizationUri).queryParam("response_type", "code")
                        .queryParam("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID)
                        .queryParam("code_challenge_method", "S256")
                        .queryParam("code_challenge", getCodeChallenge())
                        .build();
            }

            @Override
            public String buildEndpointParamsForToken(String code) {
                return "grant_type=authorization_code"
                        + "&client_id=" + URLEncoder.encode(MockCredentials.DEFAULT_CLAIM_CLIENT_ID, StandardCharsets.UTF_8)
                        + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                        + "&code_verifier=" + URLEncoder.encode(getCodeVerifier(), StandardCharsets.UTF_8);
            }
        });

        FlowProfiles.assertAccessTokenValidClaims(response);
    }
}
