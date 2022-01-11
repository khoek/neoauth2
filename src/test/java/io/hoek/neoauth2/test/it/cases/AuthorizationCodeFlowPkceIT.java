package io.hoek.neoauth2.test.it.cases;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.hoek.neoauth2.endpoint.AuthorizationRequestParser;
import io.hoek.neoauth2.endpoint.ext.OAuth21SpecOptIn;
import io.hoek.neoauth2.endpoint.ext.OAuth21SpecViolation;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.test.it.FlowProfiles;
import io.hoek.neoauth2.test.it.FlowSimulator;
import io.hoek.neoauth2.test.it.MockCredentials;
import io.hoek.neoauth2.model.ErrorResponse;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AuthorizationCodeFlowPkceIT {

    private static Stream<Arguments> getAllTestExtensions() {
        return Stream.of(
                Arguments.of(List.of()),
                Arguments.of(List.of(
                        OAuth21SpecOptIn.allowPlainCodeChallengeMethod())),
                Arguments.of(List.of(
                        OAuth21SpecViolation.dontRequirePkce())),
                Arguments.of(List.of(
                        OAuth21SpecOptIn.allowPlainCodeChallengeMethod(),
                        OAuth21SpecViolation.dontRequirePkce()))
        );
    }

    private static Stream<Arguments> getDontRequirePkceTestExtensions() {
        return Stream.of(
                Arguments.of(List.of(
                        OAuth21SpecViolation.dontRequirePkce())),
                Arguments.of(List.of(
                        OAuth21SpecOptIn.allowPlainCodeChallengeMethod(),
                        OAuth21SpecViolation.dontRequirePkce()))
        );
    }

    private static Stream<Arguments> getRequirePkceTestExtensions() {
        return Stream.of(
                Arguments.of(List.of()),
                Arguments.of(List.of(
                        OAuth21SpecOptIn.allowPlainCodeChallengeMethod()))
        );
    }

    private static Stream<Arguments> getPlainTestExtensions() {
        return Stream.of(
                Arguments.of(List.of(
                        OAuth21SpecOptIn.allowPlainCodeChallengeMethod())),
                Arguments.of(List.of(
                        OAuth21SpecOptIn.allowPlainCodeChallengeMethod(),
                        OAuth21SpecViolation.dontRequirePkce()))
        );
    }

    private static Stream<Arguments> getNoPlainTestExtensions() {
        return Stream.of(
                Arguments.of(List.of()),
                Arguments.of(List.of(
                        OAuth21SpecViolation.dontRequirePkce()))
        );
    }

    @ParameterizedTest
    @MethodSource("getAllTestExtensions")
    public void testAuthorizationFlowWithPkceSuccess(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        ObjectNode response = FlowSimulator.assertFlowSucceeds(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri, extensions));
        FlowProfiles.assertAccessTokenValidClaims(response);
    }

    @ParameterizedTest
    @MethodSource("getAllTestExtensions")
    public void testAuthorizationFlowWithPkceSuccessPlusNonce(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        String nonce = Util.calculateRandomBytesBase64UrlEncodedWithoutPadding(new SecureRandom(), 32);

        Function<URI, FlowSimulator.Profile> profileBuilder = redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri, extensions) {
            @Override
            public URI buildEndpointParamsForAuthorization(URI authorizationUri) {
                return UriBuilder.fromUri(authorizationUri).queryParam("response_type", "code")
                        .queryParam("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID)
                        .queryParam("redirect_uri", redirectUri)
                        .queryParam("code_challenge_method", "S256")
                        .queryParam("code_challenge", getCodeChallenge())
                        .queryParam("nonce", nonce)
                        .build();
            }
        };

        JwtClaims claims = FlowProfiles.assertAccessTokenValidClaims(FlowSimulator.assertFlowSucceeds(profileBuilder));
        assertEquals(nonce, claims.getClaimValueAsString("nonce"));
    }

    @ParameterizedTest
    @MethodSource("getAllTestExtensions")
    public void testAuthorizationFlowWithPkceMissingChallenge(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        ErrorResponse er = FlowSimulator.assertFlowFailsAtAuthorizationEndpoint(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri, extensions) {
            @Override
            public URI buildEndpointParamsForAuthorization(URI authorizationUri) {
                return UriBuilder.fromUri(authorizationUri).queryParam("response_type", "code")
                        .queryParam("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID)
                        .queryParam("redirect_uri", redirectUri)
                        .queryParam("code_challenge_method", "S256")
                        .build();
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "missing 'code_challenge'", null), er);
    }

    @ParameterizedTest
    @MethodSource("getAllTestExtensions")
    public void testAuthorizationFlowWithPkceMissingVerifier(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        ErrorResponse er = FlowSimulator.assertFlowFailsAtTokenEndpoint(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri, extensions) {
            @Override
            public String buildEndpointParamsForToken(String code) {
                return "grant_type=authorization_code"
                        + "&client_id=" + URLEncoder.encode(MockCredentials.DEFAULT_CLAIM_CLIENT_ID, StandardCharsets.UTF_8)
                        + "&redirect_uri=" + URLEncoder.encode(redirectUri.toString(), StandardCharsets.UTF_8)
                        + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8);
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "missing 'code_verifier'", null), er);
    }

    @ParameterizedTest
    @MethodSource("getAllTestExtensions")
    public void testAuthorizationFlowWithPkceMissingRedirectUri(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        ErrorResponse er = FlowSimulator.assertFlowFailsAtTokenEndpoint(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri, extensions) {
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

    @ParameterizedTest
    @MethodSource("getNoPlainTestExtensions")
    public void testAuthorizationFlowWithPkceNoMethodPlainNotEnabled(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        ErrorResponse er = FlowSimulator.assertFlowFailsAtAuthorizationEndpoint(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri, extensions) {
            @Override
            public URI buildEndpointParamsForAuthorization(URI authorizationUri) {
                return UriBuilder.fromUri(authorizationUri).queryParam("response_type", "code")
                        .queryParam("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID)
                        .queryParam("redirect_uri", redirectUri)
                        .queryParam("code_challenge", getCodeChallenge()).build();
            }

            @Override
            public String buildEndpointParamsForToken(String code) {
                return "grant_type=authorization_code"
                        + "&client_id=" + URLEncoder.encode(MockCredentials.DEFAULT_CLAIM_CLIENT_ID, StandardCharsets.UTF_8)
                        + "&redirect_uri=" + URLEncoder.encode(redirectUri.toString(), StandardCharsets.UTF_8)
                        + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                        + "&code_verifier=" + URLEncoder.encode(getCodeChallenge(), StandardCharsets.UTF_8);
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "challenge code method 'plain' disallowed", null), er);
    }

    @ParameterizedTest
    @MethodSource("getPlainTestExtensions")
    public void testAuthorizationFlowWithPkceNoMethodPlainEnabled(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        FlowProfiles.assertAccessTokenValidClaims(FlowSimulator.assertFlowSucceeds(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri, extensions) {
            @Override
            public URI buildEndpointParamsForAuthorization(URI authorizationUri) {
                return UriBuilder.fromUri(authorizationUri).queryParam("response_type", "code")
                        .queryParam("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID)
                        .queryParam("redirect_uri", redirectUri)
                        .queryParam("code_challenge", getCodeChallenge()).build();
            }

            @Override
            public String buildEndpointParamsForToken(String code) {
                return "grant_type=authorization_code"
                        + "&client_id=" + URLEncoder.encode(MockCredentials.DEFAULT_CLAIM_CLIENT_ID, StandardCharsets.UTF_8)
                        + "&redirect_uri=" + URLEncoder.encode(redirectUri.toString(), StandardCharsets.UTF_8)
                        + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                        + "&code_verifier=" + URLEncoder.encode(getCodeChallenge(), StandardCharsets.UTF_8);
            }
        }));
    }

    @ParameterizedTest
    @MethodSource("getDontRequirePkceTestExtensions")
    public void testAuthorizationFlowWithPkceMissingChallengeAndMethodDontRequirePkce(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        ErrorResponse er = FlowSimulator.assertFlowFailsAtTokenEndpoint(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri, extensions) {
            @Override
            public URI buildEndpointParamsForAuthorization(URI authorizationUri) {
                return UriBuilder.fromUri(authorizationUri).queryParam("response_type", "code")
                        .queryParam("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID)
                        .queryParam("redirect_uri", redirectUri)
                        .build();
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "missing 'code_challenge' from authorization", null), er);
    }

    @ParameterizedTest
    @MethodSource("getRequirePkceTestExtensions")
    public void testAuthorizationFlowWithPkceMissingChallengeAndMethodRequirePkce(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        ErrorResponse er = FlowSimulator.assertFlowFailsAtAuthorizationEndpoint(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri, extensions) {
            @Override
            public URI buildEndpointParamsForAuthorization(URI authorizationUri) {
                return UriBuilder.fromUri(authorizationUri).queryParam("response_type", "code")
                        .queryParam("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID)
                        .queryParam("redirect_uri", redirectUri)
                        .build();
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "missing 'code_challenge'", null), er);
    }

    @ParameterizedTest
    @MethodSource("getAllTestExtensions")
    public void testAuthorizationFlowWithPkceWrongVerifierIsChallengeInstead(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        ErrorResponse er = FlowSimulator.assertFlowFailsAtTokenEndpoint(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri, extensions) {
            @Override
            public String buildEndpointParamsForToken(String code) {
                return "grant_type=authorization_code"
                        + "&client_id=" + URLEncoder.encode(MockCredentials.DEFAULT_CLAIM_CLIENT_ID, StandardCharsets.UTF_8)
                        + "&redirect_uri=" + URLEncoder.encode(redirectUri.toString(), StandardCharsets.UTF_8)
                        + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                        + "&code_verifier=" + URLEncoder.encode(getCodeChallenge(), StandardCharsets.UTF_8);
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "code challenge validation failed", null), er);
    }

    @Test
    public void testAuthorizationFlowSuccessNoPkce() throws IOException {
        FlowProfiles.assertAccessTokenValidClaims(FlowSimulator.assertFlowSucceeds(redirectUri -> new FlowProfiles.StandardPkceFlow(redirectUri,
                OAuth21SpecViolation.dontRequirePkce()) {
            @Override
            public URI buildEndpointParamsForAuthorization(URI authorizationUri) {
                return UriBuilder.fromUri(authorizationUri).queryParam("response_type", "code")
                        .queryParam("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID)
                        .queryParam("redirect_uri", redirectUri)
                        .build();
            }

            @Override
            public String buildEndpointParamsForToken(String code) {
                return "grant_type=authorization_code"
                        + "&client_id=" + URLEncoder.encode(MockCredentials.DEFAULT_CLAIM_CLIENT_ID, StandardCharsets.UTF_8)
                        + "&redirect_uri=" + URLEncoder.encode(redirectUri.toString(), StandardCharsets.UTF_8)
                        + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8);
            }
        }));
    }
}
