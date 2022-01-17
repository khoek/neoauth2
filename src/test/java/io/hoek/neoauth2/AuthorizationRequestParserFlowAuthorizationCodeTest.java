package io.hoek.neoauth2;

import com.google.common.collect.Streams;
import io.hoek.neoauth2.exception.WritableWebApplicationException;
import io.hoek.neoauth2.exception.WritableWebApplicationException.JsonPage;
import io.hoek.neoauth2.extension.OAuth21SpecOptIn;
import io.hoek.neoauth2.extension.OAuth21SpecViolation;
import io.hoek.neoauth2.model.CodeChallengeMethod;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.model.PkceInfo;
import io.hoek.neoauth2.test.MockCredentials;
import io.hoek.neoauth2.test.Param;
import io.hoek.neoauth2.test.TestUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class AuthorizationRequestParserFlowAuthorizationCodeTest {

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

    private static Stream<Arguments> getRequirePkceTestExtensions() {
        return Stream.of(
                Arguments.of(List.of()),
                Arguments.of(List.of(
                        OAuth21SpecOptIn.allowPlainCodeChallengeMethod()))
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

    private static Stream<Arguments> getNoPlainTestExtensions() {
        return Stream.of(
                Arguments.of(List.of()),
                Arguments.of(List.of(
                        OAuth21SpecViolation.dontRequirePkce()))
        );
    }

    private static Stream<Arguments> getSuccessWithOptionalParamsArgs() {
        return Stream.of(
                Arguments.of(true, false, true, null, null),
                Arguments.of(true, true, false, null, null),
                Arguments.of(true, false, false, null, null),
                Arguments.of(false, false, true, null, null),
                Arguments.of(true, false, true, TestUtil.getRandom32Bytes(), null),
                Arguments.of(true, true, false, TestUtil.getRandom32Bytes(), null),
                Arguments.of(true, false, false, TestUtil.getRandom32Bytes(), null),
                Arguments.of(false, false, true, TestUtil.getRandom32Bytes(), null),
                Arguments.of(true, false, true, null, TestUtil.getRandom32Bytes()),
                Arguments.of(true, true, false, null, TestUtil.getRandom32Bytes()),
                Arguments.of(true, false, false, null, TestUtil.getRandom32Bytes()),
                Arguments.of(false, false, true, null, TestUtil.getRandom32Bytes()),
                Arguments.of(true, false, true, TestUtil.getRandom32Bytes(), TestUtil.getRandom32Bytes()),
                Arguments.of(true, true, false, TestUtil.getRandom32Bytes(), TestUtil.getRandom32Bytes()),
                Arguments.of(true, false, false, TestUtil.getRandom32Bytes(), TestUtil.getRandom32Bytes()),
                Arguments.of(false, false, true, TestUtil.getRandom32Bytes(), TestUtil.getRandom32Bytes())
        );
    }

    private static Stream<Arguments> getSuccessNoPkceArgs() {
        return TestUtil.prependArguments(getDontRequirePkceTestExtensions(),
                        TestUtil.flatPrefixProductStream(
                                Stream.of(null, TestUtil.getRandom32Bytes()),
                                Stream.of(null, TestUtil.getRandom32Bytes()).map(Arrays::asList)))
                .map(list -> Arguments.of(list.toArray()));
    }

    @ParameterizedTest
    @MethodSource("getSuccessWithOptionalParamsArgs")
    public void testSuccessWithOptionalParams(boolean allowPlain, boolean usePlain, boolean useS256, String state, String nonce) {
        String codeChallenge = TestUtil.getRandom32Bytes();

        AuthorizationRequest request = assertDoesNotThrow(() -> AuthorizationRequest.parser()
                .addExtensions(allowPlain ? List.of(OAuth21SpecOptIn.allowPlainCodeChallengeMethod()) : List.of())
                .parse(
                        clientId -> new MockCredentials.MockClientInfo() {
                            @Override
                            public @NonNull Collection<URI> getAllowedRedirectUris() {
                                return List.of(MockCredentials.DEFAULT_REDIRECT_URI);
                            }
                        },
                        new Param.MockReader(Stream.concat(
                                Streams.concat(Stream.of(
                                                new Param("response_type", "code"),
                                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                                new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString()),
                                                new Param("code_challenge", codeChallenge)),
                                        Streams.concat(
                                                usePlain ? Stream.of(new Param("code_challenge_method", "plain")) : Stream.of(),
                                                useS256 ? Stream.of(new Param("code_challenge_method", "S256")) : Stream.of()
                                        )),
                                Stream.concat(
                                        state == null ? Stream.of() : Stream.of(new Param("state", state)),
                                        nonce == null ? Stream.of() : Stream.of(new Param("nonce", nonce)))
                        ).collect(Collectors.toUnmodifiableList()))));

        assertEquals(new AuthorizationRequest.AuthorizationCode(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        true,
                        MockCredentials.DEFAULT_REDIRECT_URI,
                        MockCredentials.DEFAULT_SCOPES,
                        state,
                        nonce,
                        new PkceInfo(useS256 ? CodeChallengeMethod.S256 : CodeChallengeMethod.PLAIN, codeChallenge)),
                request);
    }

    @ParameterizedTest
    @MethodSource("getSuccessNoPkceArgs")
    public void testSuccessNoPkce(List<AuthorizationRequestParser.Extension> extensions, String state, String nonce) {
        AuthorizationRequest request = assertDoesNotThrow(() -> AuthorizationRequest.parser().addExtensions(extensions)
                .parse(
                        clientId -> new MockCredentials.MockClientInfo() {
                            @Override
                            public @NonNull Collection<URI> getAllowedRedirectUris() {
                                return List.of(MockCredentials.DEFAULT_REDIRECT_URI);
                            }
                        },
                        new Param.MockReader(Streams.concat(
                                Stream.of(
                                        new Param("response_type", "code"),
                                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                        new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString())),
                                Stream.concat(
                                        state == null ? Stream.of() : Stream.of(new Param("state", state)),
                                        nonce == null ? Stream.of() : Stream.of(new Param("nonce", nonce)))
                        ).collect(Collectors.toUnmodifiableList()))));

        assertEquals(new AuthorizationRequest.AuthorizationCode(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        true,
                        MockCredentials.DEFAULT_REDIRECT_URI,
                        MockCredentials.DEFAULT_SCOPES,
                        state,
                        nonce,
                        null),
                request);
    }

    @Test
    public void testSuccessCustomScopes() {
        String codeChallenge = TestUtil.getRandom32Bytes();
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        AuthorizationRequest request = assertDoesNotThrow(() -> AuthorizationRequest.parser().parse(
                clientId -> new MockCredentials.MockClientInfo() {
                    @Override
                    public @NonNull Collection<URI> getAllowedRedirectUris() {
                        return List.of(MockCredentials.DEFAULT_REDIRECT_URI);
                    }
                },
                new Param.MockReader(Stream.of(
                        new Param("response_type", "code"),
                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                        new Param("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString()),
                        new Param("code_challenge_method", "S256"),
                        new Param("code_challenge", codeChallenge),
                        new Param("scope", "XXXSCOPE1 scope2"),
                        new Param("state", state),
                        new Param("nonce", nonce)
                ).collect(Collectors.toUnmodifiableList()))));

        assertEquals(new AuthorizationRequest.AuthorizationCode(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        true,
                        MockCredentials.DEFAULT_REDIRECT_URI,
                        List.of("XXXSCOPE1", "scope2"),
                        state,
                        nonce,
                        new PkceInfo(CodeChallengeMethod.S256, codeChallenge)),
                request);
    }

    @Test
    public void testFailDuplicatedState() {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.JsonPage.class, () ->
                AuthorizationRequest.parser().parse(
                        MockCredentials.DEFAULT_REGISTRATION_AUTHORITY,
                        new Param.MockReader(List.of(
                                new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "http://localhost/redirect_endpoint"),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", TestUtil.getRandom32Bytes()),
                                new Param("state", state),
                                new Param("state", state),
                                new Param("nonce", nonce)))))
                .getContent();

        assertEquals(new ErrorResponse("invalid_request", "duplicate param 'state'", null), er);
    }

    @Test
    public void testFailUnregisteredClient() {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.JsonPage.class, () ->
                AuthorizationRequest.parser().parse(
                        clientId -> null,
                        new Param.MockReader(List.of(
                                new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "http://localhost/redirect_endpoint"),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", TestUtil.getRandom32Bytes()),
                                new Param("state", state),
                                new Param("nonce", nonce)))))
                .getContent();

        assertEquals(new ErrorResponse("invalid_client", "client unknown", state), er);
    }

    @Test
    public void testFailUnknownResponseType() {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.Redirect.class, () ->
                AuthorizationRequest.parser().parse(
                        MockCredentials.DEFAULT_REGISTRATION_AUTHORITY,
                        new Param.MockReader(List.of(
                                new Param("response_type", "anewone_special"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "http://localhost/redirect_endpoint"),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", TestUtil.getRandom32Bytes()),
                                new Param("state", state),
                                new Param("nonce", nonce)))))
                .getContent();

        assertEquals(new ErrorResponse("unsupported_response_type", "unsupported response type 'anewone_special'", state), er);
    }

    @Test
    public void testFailMissingResponseType() {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.Redirect.class, () ->
                AuthorizationRequest.parser().parse(
                        MockCredentials.DEFAULT_REGISTRATION_AUTHORITY,
                        new Param.MockReader(List.of(
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "http://localhost/redirect_endpoint"),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", TestUtil.getRandom32Bytes()),
                                new Param("state", state),
                                new Param("nonce", nonce)))))
                .getContent();

        assertEquals(new ErrorResponse("invalid_request", "missing 'response_type'", state), er);
    }

    @Test
    public void testFailNoDefaultScopes() {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.Redirect.class, () ->
                AuthorizationRequest.parser().parse(
                        clientId -> new MockCredentials.MockClientInfo() {
                            @Override
                            public List<String> getDefaultScopes() {
                                return null;
                            }
                        },
                        new Param.MockReader(List.of(
                                new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "http://localhost/redirect_endpoint"),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", TestUtil.getRandom32Bytes()),
                                new Param("state", state),
                                new Param("nonce", nonce)))))
                .getContent();

        assertEquals(new ErrorResponse("invalid_scope", "no 'scope' specified", state), er);
    }

    @Test
    public void testAuthorizationFlowWithPkceMissingResponseType() {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.Redirect.class, () ->
                AuthorizationRequest.parser().parse(
                        MockCredentials.DEFAULT_REGISTRATION_AUTHORITY,
                        new Param.MockReader(List.of(
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "http://localhost/redirect_endpoint"),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", TestUtil.getRandom32Bytes()),
                                new Param("state", state),
                                new Param("nonce", nonce)
                        )))).getContent();

        assertEquals(new ErrorResponse("invalid_request", "missing 'response_type'", state), er);
    }

    @Test
    public void testAuthorizationFlowWithPkceUnknownResponseType() {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.Redirect.class, () ->
                AuthorizationRequest.parser().parse(
                        MockCredentials.DEFAULT_REGISTRATION_AUTHORITY,
                        new Param.MockReader(List.of(new Param("response_type", "fancypants"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "http://localhost/redirect_endpoint"),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", TestUtil.getRandom32Bytes()),
                                new Param("state", state),
                                new Param("nonce", nonce)
                        )))).getContent();

        assertEquals(new ErrorResponse("unsupported_response_type", "unsupported response type 'fancypants'", state), er);
    }

    @Test
    public void testAuthorizationFlowWithPkceUnknownCodeChallengeMethod() {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.Redirect.class, () ->
                AuthorizationRequest.parser().parse(
                        MockCredentials.DEFAULT_REGISTRATION_AUTHORITY,
                        new Param.MockReader(List.of(new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "http://localhost/redirect_endpoint"),
                                new Param("code_challenge_method", "pantaloon17"),
                                new Param("code_challenge", TestUtil.getRandom32Bytes()),
                                new Param("state", state),
                                new Param("nonce", nonce)
                        )))).getContent();

        assertEquals(new ErrorResponse("invalid_request", "unsupported code challenge method 'pantaloon17'", state), er);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "tooshort",
            "toolongxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    })
    public void testAuthorizationFlowWithPkceCodeChallangeBadLength(String challenge) {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.Redirect.class, () ->
                AuthorizationRequest.parser().parse(
                        MockCredentials.DEFAULT_REGISTRATION_AUTHORITY,
                        new Param.MockReader(List.of(new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "http://localhost/redirect_endpoint"),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", challenge),
                                new Param("state", state),
                                new Param("nonce", nonce)
                        )))).getContent();

        assertEquals(new ErrorResponse("invalid_request", "code challenge less than 43 or greater than 128 characters", state), er);
    }

    @ParameterizedTest
    @MethodSource("getAllTestExtensions")
    public void testAuthorizationFlowWithPkceMissingChallenge(List<AuthorizationRequestParser.Extension> extensions) {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.Redirect.class, () ->
                AuthorizationRequest.parser().addExtensions(extensions).parse(
                        MockCredentials.DEFAULT_REGISTRATION_AUTHORITY,
                        new Param.MockReader(List.of(new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "http://localhost/redirect_endpoint"),
                                new Param("code_challenge_method", "S256"),
                                new Param("state", state),
                                new Param("nonce", nonce)
                        )))).getContent();

        assertEquals(new ErrorResponse("invalid_request", "missing 'code_challenge'", state), er);
    }

    @ParameterizedTest
    @MethodSource("getNoPlainTestExtensions")
    public void testAuthorizationFlowWithPkceNoMethodPlainNotEnabled(List<AuthorizationRequestParser.Extension> extensions) {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.Redirect.class, () ->
                AuthorizationRequest.parser().addExtensions(extensions).parse(
                        MockCredentials.DEFAULT_REGISTRATION_AUTHORITY,
                        new Param.MockReader(List.of(new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "http://localhost/redirect_endpoint"),
                                new Param("code_challenge", TestUtil.getRandom32Bytes()),
                                new Param("state", state),
                                new Param("nonce", nonce)
                        )))).getContent();

        assertEquals(new ErrorResponse("invalid_request", "challenge code method 'plain' disallowed", state), er);
    }

    @ParameterizedTest
    @MethodSource("getRequirePkceTestExtensions")
    public void testAuthorizationFlowWithPkceMissingChallengeAndMethodRequirePkce(List<AuthorizationRequestParser.Extension> extensions) {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(WritableWebApplicationException.Redirect.class, () ->
                AuthorizationRequest.parser().addExtensions(extensions).parse(
                        MockCredentials.DEFAULT_REGISTRATION_AUTHORITY,
                        new Param.MockReader(List.of(new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "http://localhost/redirect_endpoint"),
                                new Param("state", state),
                                new Param("nonce", nonce)
                        )))).getContent();

        assertEquals(new ErrorResponse("invalid_request", "missing 'code_challenge'", state), er);
    }
}
