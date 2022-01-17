package io.hoek.neoauth2.test.it.cases;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.hoek.neoauth2.AuthorizationRequestParser;
import io.hoek.neoauth2.extension.OAuth21SpecOptIn;
import io.hoek.neoauth2.extension.OAuth21SpecViolation;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.test.MockCredentials;
import io.hoek.neoauth2.test.Param;
import io.hoek.neoauth2.test.it.Flows;
import io.hoek.neoauth2.test.it.MockFlows;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.List;
import java.util.Set;
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

    private static Stream<Arguments> getPlainTestExtensions() {
        return Stream.of(
                Arguments.of(List.of(
                        OAuth21SpecOptIn.allowPlainCodeChallengeMethod())),
                Arguments.of(List.of(
                        OAuth21SpecOptIn.allowPlainCodeChallengeMethod(),
                        OAuth21SpecViolation.dontRequirePkce()))
        );
    }

    @ParameterizedTest
    @MethodSource("getAllTestExtensions")
    public void testAuthorizationFlowWithPkceSuccess(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        ObjectNode response = Flows.assertAuthorizationCodeFlowSucceeds(extensions, MockFlows.StandardMockAuthorizationCodeFlow::new);
        MockCredentials.assertAccessTokenClaimsValidForDefaultIssuer(response);
    }

    @ParameterizedTest
    @MethodSource("getAllTestExtensions")
    public void testAuthorizationFlowWithPkceSuccessPlusStateAndNonce(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        String state = Util.generateRandomBytesBase64UrlEncodedWithoutPadding(new SecureRandom(), 32);
        String nonce = Util.generateRandomBytesBase64UrlEncodedWithoutPadding(new SecureRandom(), 32);

        ObjectNode response = Flows.assertAuthorizationCodeFlowSucceeds(extensions, redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {
            @Override
            public String getExpectedAuthorizationResponseState() {
                return state;
            }

            @Override
            public Collection<Param> getAuthorizationEndpointParams() {
                return Set.of(new Param("response_type", "code"),
                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                        new Param("redirect_uri", redirectUri.toString()),
                        new Param("code_challenge_method", "S256"),
                        new Param("code_challenge", getCodeChallenge()),
                        new Param("state", state),
                        new Param("nonce", nonce));
            }
        });

        JwtClaims claims = MockCredentials.assertAccessTokenClaimsValidForDefaultIssuer(response);
        // The returned value of 'state' is checked inside the `Flows` orchestrator because of our overridden
        // `getExpectedAuthorizationResponseState()`.
        assertEquals(nonce, claims.getClaimValueAsString("nonce"));
    }

    @ParameterizedTest
    @MethodSource("getAllTestExtensions")
    public void testAuthorizationFlowWithPkceMissingVerifier(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        ErrorResponse er = Flows.assertAuthorizationCodeFlowFailsAtTokenEndpoint(extensions, redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {

            @Override
            public Collection<Param> getTokenEndpointParams(String code) {
                return Set.of(new Param("grant_type", "authorization_code"),
                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                        new Param("redirect_uri", redirectUri.toString()),
                        new Param("code", code));
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "missing 'code_verifier'", null), er);
    }

    @ParameterizedTest
    @MethodSource("getAllTestExtensions")
    public void testAuthorizationFlowWithPkceMissingRedirectUri(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        ErrorResponse er = Flows.assertAuthorizationCodeFlowFailsAtTokenEndpoint(extensions, redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {

            @Override
            public Collection<Param> getTokenEndpointParams(String code) {
                return Set.of(new Param("grant_type", "authorization_code"),
                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                        new Param("code", code),
                        new Param("code_verifier", getCodeVerifier()));
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "missing 'redirect_uri'", null), er);
    }

    @ParameterizedTest
    @MethodSource("getPlainTestExtensions")
    public void testAuthorizationFlowWithPkceNoMethodPlainEnabled(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        MockCredentials.assertAccessTokenClaimsValidForDefaultIssuer(Flows.assertAuthorizationCodeFlowSucceeds(extensions,
                redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {

                    @Override
                    public Collection<Param> getAuthorizationEndpointParams() {
                        return Set.of(new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", redirectUri.toString()),
                                new Param("code_challenge", getCodeChallenge()));
                    }

                    @Override
                    public Collection<Param> getTokenEndpointParams(String code) {
                        return Set.of(new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", redirectUri.toString()),
                                new Param("code", code),
                                new Param("code_verifier", getCodeChallenge()));
                    }
                }));
    }

    @ParameterizedTest
    @MethodSource("getDontRequirePkceTestExtensions")
    public void testAuthorizationFlowWithPkceMissingChallengeAndMethodDontRequirePkce(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        ErrorResponse er = Flows.assertAuthorizationCodeFlowFailsAtTokenEndpoint(extensions, redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {

            @Override
            public Collection<Param> getAuthorizationEndpointParams() {
                return Set.of(new Param("response_type", "code"),
                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                        new Param("redirect_uri", redirectUri.toString()));
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "missing 'code_challenge' from authorization", null), er);
    }

    @ParameterizedTest
    @MethodSource("getAllTestExtensions")
    public void testAuthorizationFlowWithPkceWrongVerifierIsChallengeInstead(List<AuthorizationRequestParser.Extension> extensions) throws IOException {
        ErrorResponse er = Flows.assertAuthorizationCodeFlowFailsAtTokenEndpoint(extensions, redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {
            @Override
            protected Collection<Param> getTokenEndpointParams(String code) {
                return Set.of(new Param("grant_type", "authorization_code"),
                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                        new Param("redirect_uri", redirectUri.toString()),
                        new Param("code", code),
                        new Param("code_verifier", getCodeChallenge()));
            }
        });

        assertEquals(new ErrorResponse("invalid_request", "code challenge validation failed", null), er);
    }

    @Test
    public void testAuthorizationFlowSuccessNoPkce() throws IOException {
        MockCredentials.assertAccessTokenClaimsValidForDefaultIssuer(Flows.assertAuthorizationCodeFlowSucceeds(
                List.of(OAuth21SpecViolation.dontRequirePkce()),
                redirectUri -> new MockFlows.StandardMockAuthorizationCodeFlow(redirectUri) {

                    @Override
                    public Collection<Param> getAuthorizationEndpointParams() {
                        return Set.of(new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", redirectUri.toString()));
                    }

                    @Override
                    protected Collection<Param> getTokenEndpointParams(String code) {
                        return Set.of(new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", redirectUri.toString()),
                                new Param("code", code));
                    }
                }));
    }
}
