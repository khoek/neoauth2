package io.hoek.neoauth2;

import io.hoek.neoauth2.extension.OAuth21SpecViolation;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.test.MockCredentials;
import io.hoek.neoauth2.test.Param;
import io.hoek.neoauth2.test.TestUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class AuthorizationRequestParserFlowImplicitTest {

    public static final URI DEFAULT_REDIRECT_URI = URI.create("http://localhost/redirect_endpoint");

    private static Stream<Arguments> getRequireNonceTestExtensions() {
        return Stream.of(
                List.of(OAuth21SpecViolation.allowImplicit()),
                List.of(OAuth21SpecViolation.allowImplicit(), OAuth21SpecViolation.dontRequirePkce()),
                List.of(OAuth21SpecViolation.allowImplicit(true)),
                List.of(OAuth21SpecViolation.allowImplicit(true), OAuth21SpecViolation.dontRequirePkce())
        ).map(Arguments::of);
    }

    private static Stream<Arguments> getAllTestExtensions() {
        return Stream.of(
                List.of(OAuth21SpecViolation.allowImplicit()),
                List.of(OAuth21SpecViolation.allowImplicit(), OAuth21SpecViolation.dontRequirePkce()),
                List.of(OAuth21SpecViolation.allowImplicit(true)),
                List.of(OAuth21SpecViolation.allowImplicit(true), OAuth21SpecViolation.dontRequirePkce()),
                List.of(OAuth21SpecViolation.allowImplicit(false)),
                List.of(OAuth21SpecViolation.allowImplicit(false), OAuth21SpecViolation.dontRequirePkce())
        ).map(Arguments::of);
    }

    private static Stream<Arguments> getImplicitWithCodeChallangeAndMethodArgs() {
        return TestUtil.prependArguments(getAllTestExtensions(), Stream.of(
                        List.of(List.of(new Param("code_challenge_method", "S256"))),
                        List.of(List.of(new Param("code_challenge", "04d1cf61576663c6fa649f01e91de68c2970a33489dabde81cf5aaa5a4cf6242"))),
                        List.of(List.of(new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", "04d1cf61576663c6fa649f01e91de68c2970a33489dabde81cf5aaa5a4cf6242")))))
                .map(list -> Arguments.of(list.toArray()));
    }

    @Test
    public void testImplicitMissingNonceAllowedSuccess() {
        String state = TestUtil.getRandom32Bytes();

        AuthorizationRequest response = assertDoesNotThrow(() ->
                AuthorizationRequest.parser().addExtension(OAuth21SpecViolation.allowImplicit(false)).parse(
                        MockCredentials.DEFAULT_CLIENT_REGISTRATION,
                        new Param.MockReader(List.of(new Param("response_type", "token"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", DEFAULT_REDIRECT_URI.toString()),
                                new Param("state", state)
                        )))).getRequest();

        assertEquals(new AuthorizationRequest.Implicit(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        true,
                        DEFAULT_REDIRECT_URI,
                        MockCredentials.DEFAULT_SCOPES,
                        state,
                        null),
                response);
    }

    @ParameterizedTest
    @MethodSource("getRequireNonceTestExtensions")
    public void testImplicitFailsAndPreservesState(List<AuthorizationRequestParser.Extension> extensions) {
        String state = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.Redirect.class, () ->
                AuthorizationRequest.parser().addExtensions(extensions).parse(
                        MockCredentials.DEFAULT_CLIENT_REGISTRATION,
                        new Param.MockReader(List.of(new Param("response_type", "token"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", DEFAULT_REDIRECT_URI.toString()),
                                new Param("state", state)
                        )))).getContent();

        assertEquals(new ErrorResponse("invalid_request", "parameter 'nonce' required for implicit grant", state), er);
    }

    @ParameterizedTest
    @MethodSource("getAllTestExtensions")
    public void testImplicitNonceSuccess(List<AuthorizationRequestParser.Extension> extensions) {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        AuthorizationRequest response = assertDoesNotThrow(() ->
                AuthorizationRequest.parser().addExtensions(extensions).parse(
                        MockCredentials.DEFAULT_CLIENT_REGISTRATION,
                        new Param.MockReader(List.of(new Param("response_type", "token"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", DEFAULT_REDIRECT_URI.toString()),
                                new Param("state", state),
                                new Param("nonce", nonce))))).getRequest();

        assertEquals(new AuthorizationRequest.Implicit(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        true,
                        DEFAULT_REDIRECT_URI,
                        MockCredentials.DEFAULT_SCOPES,
                        state,
                        nonce),
                response);
    }

    @Test
    public void testImplicitNotEnabled() {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.Redirect.class, () ->
                AuthorizationRequest.parser().parse(
                        MockCredentials.DEFAULT_CLIENT_REGISTRATION,
                        new Param.MockReader(List.of(new Param("response_type", "token"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", DEFAULT_REDIRECT_URI.toString()),
                                new Param("state", state),
                                new Param("nonce", nonce))))).getContent();

        assertEquals(new ErrorResponse("invalid_request", "response type 'token' disallowed", state), er);
    }

    @ParameterizedTest
    @MethodSource("getImplicitWithCodeChallangeAndMethodArgs")
    public void testImplicitWithCodeChallangeAndMethod(List<AuthorizationRequestParser.Extension> extensions, List<Param> extraParams) {
        String state = TestUtil.getRandom32Bytes();
        String nonce = TestUtil.getRandom32Bytes();

        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.Redirect.class, () ->
                AuthorizationRequest.parser().addExtensions(extensions).parse(
                        MockCredentials.DEFAULT_CLIENT_REGISTRATION,
                        new Param.MockReader(Stream.concat(Stream.of(
                                                new Param("response_type", "token"),
                                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                                new Param("redirect_uri", DEFAULT_REDIRECT_URI.toString()),
                                                new Param("state", state),
                                                new Param("nonce", nonce)),
                                        extraParams.stream())
                                .collect(Collectors.toUnmodifiableList())))).getContent();

        assertEquals(new ErrorResponse("invalid_request", "implicit flow doesn't support PKCE", state), er);
    }
}
