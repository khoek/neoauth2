package io.hoek.neoauth2;

import com.google.common.collect.Streams;
import io.hoek.neoauth2.backend.AuthorizationCodeIssuer;
import io.hoek.neoauth2.backend.AuthorizationCodeOrder;
import io.hoek.neoauth2.exception.WritableWebApplicationException;
import io.hoek.neoauth2.exception.WritableWebApplicationException.JsonPage;
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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class TokenRequestParserFlowAuthorizationCodeTest {

    public static final class MockAuthorizationCodeVerifier implements AuthorizationCodeIssuer {
        public static final String MAGIC_CODE = TestUtil.getRandom32Bytes();

        private final AuthorizationCodeOrder order;

        public MockAuthorizationCodeVerifier(AuthorizationCodeOrder order) {
            this.order = order;
        }

        @Override
        public AuthorizationCodePayload issueAuthorizationCode(AuthorizationCodeOrder order, Instant expiry) {
            throw new UnsupportedOperationException();
        }

        @Override
        public AuthorizationCodeOrder readAndVerifyAuthorizationCode(AuthorizationCodePayload payload) {
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
    public void testSuccessWithChallengeMethodsAndOptionalNonce(CodeChallengeMethod codeChallengeMethod, String nonce) {
        String codeVerifier = TestUtil.getRandom32Bytes();
        AuthorizationCodeOrder order = new AuthorizationCodeOrder(
                MockCredentials.DEFAULT_CLAIM_SUB,
                MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                MockCredentials.DEFAULT_SCOPES,
                true,
                MockCredentials.DEFAULT_REDIRECT_URI,
                codeChallengeMethod == null ? null : new PkceInfo(codeChallengeMethod, codeChallengeMethod.calculateChallenge(codeVerifier)),
                nonce
        );

        TokenRequest response = assertDoesNotThrow(() ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
                        new Param.MockReader(Streams.concat(Stream.of(
                                        new Param("grant_type", "authorization_code"),
                                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                        new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString()),
                                        new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE)),
                                codeChallengeMethod == null ? Stream.of() : Stream.of(new Param("code_verifier", codeVerifier))
                        ).collect(Collectors.toUnmodifiableList()))
                ));

        assertEquals(new TokenRequest.AuthorizationCode(order), response);
    }

    @Test
    public void testFailMissingGrantType() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        AuthorizationCodeOrder order = MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier);

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.JsonPage.class, () ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
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
        AuthorizationCodeOrder order = MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier);

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.JsonPage.class, () ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
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
        AuthorizationCodeOrder order = MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier);

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.JsonPage.class, () ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
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
        AuthorizationCodeOrder order = MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier);

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.JsonPage.class, () ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
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
        AuthorizationCodeOrder order = new AuthorizationCodeOrder(
                MockCredentials.DEFAULT_CLAIM_SUB,
                MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                MockCredentials.DEFAULT_SCOPES,
                true,
                URI.create("https://a.random.com/redirect_endpoint"),
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier)),
                TestUtil.getRandom32Bytes()
        );

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.JsonPage.class, () ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
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
        AuthorizationCodeOrder order = new AuthorizationCodeOrder(
                MockCredentials.DEFAULT_CLAIM_SUB,
                MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                MockCredentials.DEFAULT_SCOPES,
                false,
                URI.create("https://a.random.com/redirect_endpoint"),
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier)),
                TestUtil.getRandom32Bytes()
        );

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.JsonPage.class, () ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
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
        AuthorizationCodeOrder order = new AuthorizationCodeOrder(
                MockCredentials.DEFAULT_CLAIM_SUB,
                MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                MockCredentials.DEFAULT_SCOPES,
                true,
                URI.create("https://a.random.com/redirect_endpoint"),
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier)),
                TestUtil.getRandom32Bytes()
        );

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.JsonPage.class, () ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
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
        AuthorizationCodeOrder order = new AuthorizationCodeOrder(
                MockCredentials.DEFAULT_CLAIM_SUB,
                MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                MockCredentials.DEFAULT_SCOPES,
                false,
                URI.create("https://a.random.com/redirect_endpoint"),
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier)),
                TestUtil.getRandom32Bytes()
        );

        TokenRequest response = assertDoesNotThrow(() ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE),
                                new Param("code_verifier", codeVerifier)
                        ))
                ));

        assertEquals(new TokenRequest.AuthorizationCode(order), response);
    }

    @Test
    public void testFailMalformedRedirectUri() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        AuthorizationCodeOrder order = MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier);

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.JsonPage.class, () ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
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
        AuthorizationCodeOrder order = MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier);

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.JsonPage.class, () ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
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
        AuthorizationCodeOrder order = MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier);

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.JsonPage.class, () ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
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
        AuthorizationCodeOrder order = new AuthorizationCodeOrder(
                MockCredentials.DEFAULT_CLAIM_SUB,
                MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                MockCredentials.DEFAULT_SCOPES,
                true,
                MockCredentials.DEFAULT_REDIRECT_URI,
                null,
                TestUtil.getRandom32Bytes()
        );

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.JsonPage.class, () ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
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
        AuthorizationCodeOrder order = new AuthorizationCodeOrder(
                MockCredentials.DEFAULT_CLAIM_SUB,
                MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                customScopes,
                true,
                MockCredentials.DEFAULT_REDIRECT_URI,
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier)),
                TestUtil.getRandom32Bytes()
        );

        TokenRequest response = assertDoesNotThrow(() ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
                        new Param.MockReader(List.of(
                                new Param("grant_type", "authorization_code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString()),
                                new Param("scope", String.join(" ", customScopes)),
                                new Param("code", MockAuthorizationCodeVerifier.MAGIC_CODE),
                                new Param("code_verifier", codeVerifier)
                        ))
                ));

        assertEquals(new TokenRequest.AuthorizationCode(order), response);
    }

    @Test
    public void testFailCustomMismatchedScopes() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        AuthorizationCodeOrder order = new AuthorizationCodeOrder(
                MockCredentials.DEFAULT_CLAIM_SUB,
                MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                List.of("31337Haxxor77scopeA"),
                true,
                MockCredentials.DEFAULT_REDIRECT_URI,
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier)),
                TestUtil.getRandom32Bytes()
        );

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.JsonPage.class, () ->
                TokenRequest.parser().parse(new MockAuthorizationCodeVerifier(order),
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
