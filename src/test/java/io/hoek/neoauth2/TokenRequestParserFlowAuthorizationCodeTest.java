package io.hoek.neoauth2;

import com.google.common.collect.Streams;
import io.hoek.neoauth2.backend.AuthorizationAuthority;
import io.hoek.neoauth2.backend.UserAuthorization;
import io.hoek.neoauth2.backend.IssuerBundle;
import io.hoek.neoauth2.backend.TokenSpec;
import io.hoek.neoauth2.model.AuthorizationCodePayload;
import io.hoek.neoauth2.model.CodeChallengeMethod;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.model.PkceInfo;
import io.hoek.neoauth2.test.MockCredentials;
import io.hoek.neoauth2.test.Param;
import io.hoek.neoauth2.test.TestUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class TokenRequestParserFlowAuthorizationCodeTest {

    public static IssuerBundle getMockIssuerBundle(UserAuthorization order) {
        return IssuerBundle.with(
                new MockAuthorizationCodeVerifier(order),
                o -> {
                    throw new UnsupportedOperationException();
                });
    }

    public static final class MockAuthorizationCodeVerifier implements AuthorizationAuthority {

        public static final String MAGIC_CODE = TestUtil.getRandom32Bytes();

        private final UserAuthorization order;

        public MockAuthorizationCodeVerifier(UserAuthorization order) {
            this.order = order;
        }

        @Override
        public AuthorizationCodePayload issueAuthorizationCode(UserAuthorization order, Instant expiry) {
            throw new UnsupportedOperationException();
        }

        @Override
        public UserAuthorization readAndVerifyAuthorizationCode(AuthorizationCodePayload payload) {
            if (payload.getCode().equals(MAGIC_CODE)) {
                return order;
            }

            return null;
        }
    }

    private static Stream<Arguments> getSuccessWithChallengeMethodsAndOptionalNonce() {
        return Stream.of(
                Arguments.of(CodeChallengeMethod.S256, null),
                Arguments.of(CodeChallengeMethod.S256, TestUtil.getRandom32Bytes()),
                Arguments.of(CodeChallengeMethod.PLAIN, null),
                Arguments.of(CodeChallengeMethod.PLAIN, TestUtil.getRandom32Bytes()),
                Arguments.of(null, null),
                Arguments.of(null, TestUtil.getRandom32Bytes())
        );
    }

    @ParameterizedTest
    @MethodSource("getSuccessWithChallengeMethodsAndOptionalNonce")
    @SuppressWarnings("unchecked")
    public void testSuccessWithChallengeMethodsAndOptionalNonce(CodeChallengeMethod codeChallengeMethod, String nonce) {
        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = new UserAuthorization(
                new TokenSpec(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        MockCredentials.DEFAULT_SCOPES,
                        Map.ofEntries(Stream.concat(
                                        Stream.of(Map.entry("sub", MockCredentials.DEFAULT_CLAIM_SUB)),
                                        nonce == null ? Stream.of() : Stream.of(Map.entry("nonce", nonce))
                                ).toArray(Map.Entry[]::new))),
                true,
                MockCredentials.DEFAULT_REDIRECT_URI,
                codeChallengeMethod == null ? null : new PkceInfo(codeChallengeMethod, codeChallengeMethod.calculateChallenge(codeVerifier))
        );

        TokenRequest response = assertDoesNotThrow(() ->
                TokenRequest.parser().parse(
                        getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(Streams.concat(Stream.of(
                                        new Param("grant_type", "authorization_code"),
                                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                        new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString()),
                                        new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE)),
                                codeChallengeMethod == null ? Stream.of() : Stream.of(new Param("code_verifier", codeVerifier))
                        ).collect(Collectors.toUnmodifiableList()))
                )).getRequest();

        assertEquals(new TokenRequest.AuthorizationCode(order), response);
    }

    @Test
    public void testFailMissingGrantType() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier);

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                TokenRequest.parser().parse(
                        getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(List.of(
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString()),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE),
                                new Param("code_verifier", codeVerifier)
                        ))
                )).getContent();

        assertEquals(new ErrorResponse("invalid_request", "missing 'grant_type'", null), er);
    }

    @Test
    public void testFailUnknownGrantType() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier);

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                TokenRequest.parser().parse(getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "fancypants"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString()),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE),
                                new Param("code_verifier", codeVerifier)
                        ))
                )).getContent();

        assertEquals(new ErrorResponse("unsupported_grant_type", "unsupported grant type 'fancypants'", null), er);
    }

    @Test
    public void testFailBadCode() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier);

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                TokenRequest.parser().parse(getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString()),
                                new Param("code", "DEADBEEFDEADBEEFDEADBEEFDEADBEEF"),
                                new Param("code_verifier", codeVerifier)
                        ))
                )).getContent();

        assertEquals(new ErrorResponse("invalid_grant", "invalid code", null), er);
    }

    @Test
    public void testFailMismatchedClientId() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier);

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                TokenRequest.parser().parse(getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "authorization_code"),
                                new Param("client_id", "ALEXANDER_DEADBEEF"),
                                new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString()),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE),
                                new Param("code_verifier", codeVerifier)
                        ))
                )).getContent();

        assertEquals(new ErrorResponse("invalid_grant", "mismatched 'client_id' with authorization code", null), er);
    }

    @Test
    public void testFailMismatchedRedirectUriAndWasProvided() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = new UserAuthorization(
                new TokenSpec(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        MockCredentials.DEFAULT_SCOPES,
                        Map.of("sub", MockCredentials.DEFAULT_CLAIM_SUB, "nonce", TestUtil.getRandom32Bytes())),
                true,
                URI.create("https://a.random.com/redirect_endpoint"),
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier))
        );

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                TokenRequest.parser().parse(getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "https://another.mismatched.uri.example.com/endpoitn"),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE),
                                new Param("code_verifier", codeVerifier)
                        ))
                )).getContent();

        assertEquals(new ErrorResponse("invalid_grant", "mismatched 'redirect_uri' with authorization code", null), er);
    }

    @Test
    public void testFailMismatchedRedirectUriAndWasNotProvided() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = new UserAuthorization(
                new TokenSpec(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        MockCredentials.DEFAULT_SCOPES,
                        Map.of("sub", MockCredentials.DEFAULT_CLAIM_SUB, "nonce", TestUtil.getRandom32Bytes())),
                false,
                URI.create("https://a.random.com/redirect_endpoint"),
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier))
        );

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                TokenRequest.parser().parse(getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "https://another.mismatched.uri.example.com/endpoitn"),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE),
                                new Param("code_verifier", codeVerifier)
                        ))
                )).getContent();

        assertEquals(new ErrorResponse("invalid_grant", "'redirect_uri' does not match registered default", null), er);
    }

    @Test
    public void testFailMissingRedirectUriAndWasProvided() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = new UserAuthorization(
                new TokenSpec(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        MockCredentials.DEFAULT_SCOPES,
                        Map.of("sub", MockCredentials.DEFAULT_CLAIM_SUB, "nonce", TestUtil.getRandom32Bytes())),
                true,
                URI.create("https://a.random.com/redirect_endpoint"),
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier))
        );

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                TokenRequest.parser().parse(getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE),
                                new Param("code_verifier", codeVerifier)
                        ))
                )).getContent();

        assertEquals(new ErrorResponse("invalid_request", "missing 'redirect_uri'", null), er);
    }

    @Test
    public void testSuccessMissingRedirectUriAndWasNotProvided() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = new UserAuthorization(
                new TokenSpec(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        MockCredentials.DEFAULT_SCOPES,
                        Map.of("sub", MockCredentials.DEFAULT_CLAIM_SUB, "nonce", TestUtil.getRandom32Bytes())),
                false,
                URI.create("https://a.random.com/redirect_endpoint"),
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier))
        );

        TokenRequest response = assertDoesNotThrow(() ->
                TokenRequest.parser().parse(getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE),
                                new Param("code_verifier", codeVerifier)
                        ))
                )).getRequest();

        assertEquals(new TokenRequest.AuthorizationCode(order), response);
    }

    @Test
    public void testFailMalformedRedirectUri() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier);

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                TokenRequest.parser().parse(getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "%%%%%MALFORMED I am"),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE),
                                new Param("code_verifier", codeVerifier)
                        ))
                )).getContent();

        assertEquals(new ErrorResponse("invalid_request", "malformed 'redirect_uri'", null), er);
    }

    @Test
    public void testFailPkceWrongVerifier() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier);

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                TokenRequest.parser().parse(getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString()),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE),
                                new Param("code_verifier", TestUtil.getRandom32Bytes())
                        ))
                )).getContent();

        assertEquals(new ErrorResponse("invalid_request", "code challenge validation failed", null), er);
    }

    @Test
    public void testFailPkceMissingVerifier() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier);

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                TokenRequest.parser().parse(getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString()),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE)
                        ))
                )).getContent();

        assertEquals(new ErrorResponse("invalid_request", "missing 'code_verifier'", null), er);
    }

    @Test
    public void testFailPkceVerifierPresentButMissingInOrder() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = new UserAuthorization(
                new TokenSpec(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        MockCredentials.DEFAULT_SCOPES,
                        Map.of("sub", MockCredentials.DEFAULT_CLAIM_SUB, "nonce", TestUtil.getRandom32Bytes())),
                true,
                MockCredentials.DEFAULT_REDIRECT_URI,
                null
        );

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                TokenRequest.parser().parse(getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString()),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE),
                                new Param("code_verifier", codeVerifier)
                        ))
                )).getContent();

        assertEquals(new ErrorResponse("invalid_request", "missing 'code_challenge' from authorization", null), er);
    }

    @Test
    public void testSuccessCustomScopes() {
        List<String> customScopes = List.of("31337Haxxor77scopeA", "31337Haxxor77scopeB");

        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = new UserAuthorization(
                new TokenSpec(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        customScopes,
                        Map.of("sub", MockCredentials.DEFAULT_CLAIM_SUB, "nonce", TestUtil.getRandom32Bytes())),
                true,
                MockCredentials.DEFAULT_REDIRECT_URI,
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier))
        );

        TokenRequest response = assertDoesNotThrow(() ->
                TokenRequest.parser().parse(getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString()),
                                new Param("scope", String.join(" ", customScopes)),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE),
                                new Param("code_verifier", codeVerifier)
                        ))
                )).getRequest();

        assertEquals(new TokenRequest.AuthorizationCode(order), response);
    }

    @Test
    public void testFailCustomMismatchedScopes() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        UserAuthorization order = new UserAuthorization(
                new TokenSpec(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        List.of("31337Haxxor77scopeA"),
                        Map.of("sub", MockCredentials.DEFAULT_CLAIM_SUB, "nonce", TestUtil.getRandom32Bytes())),
                true,
                MockCredentials.DEFAULT_REDIRECT_URI,
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier))
        );

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                TokenRequest.parser().parse(getMockIssuerBundle(order),
                        new MockCredentials.MockClientRegistration(),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString()),
                                new Param("scope", String.join(" ", List.of("31337Haxxor77scopeA", "31337Haxxor77scopeB"))),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE),
                                new Param("code_verifier", codeVerifier)
                        ))
                )).getContent();

        assertEquals(new ErrorResponse("invalid_request", "mismatched 'scope' with authorization code", null), er);
    }
}
