package io.hoek.neoauth2;

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

import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class AuthorizationRequestParserRedirectUriTest {

    private static Stream<Arguments> getNoDefaultUriAllowedLists() {
        return Stream.of(
                Arguments.of(List.of()),
                Arguments.of(List.of(
                        URI.create("https://example.com/redirect_endpoint"),
                        URI.create("https://example.com/another_redirect_endpoint")))
        );
    }

    private static Stream<Arguments> getFailsValidationUrisAndErrorMessage() {
        return Stream.of(
                Arguments.of(URI.create("apricot.com/asparagus/path"), "redirect URI is not absolute"),
                Arguments.of(URI.create("https://:90?hah=fries"), "redirect URI is missing host"),
                Arguments.of(URI.create("https://test.example.com/endpoint#oopsafragment"), "redirect URI has a fragment"),
                Arguments.of(URI.create("http://not.https.com"), "redirect URI is not https")
        );
    }



    @Test
    public void testRedirectUriFailMalformed() {
        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                AuthorizationRequest.parser().parse(
                        MockCredentials.DEFAULT_CLIENT_REGISTRATION,
                        new Param.MockReader(List.of(
                                new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "%%TOTALTHUNDER"),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", TestUtil.getRandom32Bytes())))))
                .getContent();

        assertEquals(new ErrorResponse("invalid_request", "malformed redirect URI", null), er);
    }

    @Test
    public void testRedirectUriFailNotRegistered() {
        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                AuthorizationRequest.parser().parse(
                        MockCredentials.DEFAULT_CLIENT_REGISTRATION,
                        new Param.MockReader(List.of(
                                new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", "https://example.com/chillipeppers"),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", TestUtil.getRandom32Bytes())))))
                .getContent();

        assertEquals(new ErrorResponse("invalid_request", "redirect URI not registered", null), er);
    }

    @Test
    public void testRedirectUriSuccessMissingUseDefault() {
        String codeChallenge = TestUtil.getRandom32Bytes();

        AuthorizationRequest request = assertDoesNotThrow(() -> AuthorizationRequest.parser().parse(
                new MockCredentials.MockClientRegistration() {
                    @Override
                    public @NonNull @lombok.NonNull Collection<URI> getAllowedRedirectUris() {
                        return List.of(MockCredentials.DEFAULT_REDIRECT_URI);
                    }
                },
                new Param.MockReader(List.of(
                        new Param("response_type", "code"),
                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                        new Param("code_challenge_method", "S256"),
                        new Param("code_challenge", codeChallenge))))).getRequest();

        assertEquals(new AuthorizationRequest.AuthorizationCode(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        false,
                        MockCredentials.DEFAULT_REDIRECT_URI,
                        MockCredentials.DEFAULT_SCOPES,
                        null,
                        null,
                        new PkceInfo(CodeChallengeMethod.S256, codeChallenge)),
                request);
    }

    @ParameterizedTest
    @MethodSource("getNoDefaultUriAllowedLists")
    public void testRedirectUriFailMissingNoDefault(List<URI> allowedUris) {
        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                AuthorizationRequest.parser().parse(
                        new MockCredentials.MockClientRegistration() {
                            @Override
                            public @NonNull @lombok.NonNull Collection<URI> getAllowedRedirectUris() {
                                return allowedUris;
                            }
                        },
                        new Param.MockReader(List.of(
                                new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", TestUtil.getRandom32Bytes())))))
                .getContent();

        assertEquals(new ErrorResponse("invalid_request", "missing redirect URI and no default registered", null), er);
    }

    @ParameterizedTest
    @MethodSource("getFailsValidationUrisAndErrorMessage")
    public void testRedirectUriFailValidation(URI forceRedirectUri, String errorMessage) {
        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                AuthorizationRequest.parser().parse(
                        new MockCredentials.MockClientRegistration() {
                            @Override
                            public @NonNull @lombok.NonNull Collection<URI> getAllowedRedirectUris() {
                                return List.of(forceRedirectUri);
                            }
                        },
                        new Param.MockReader(List.of(
                                new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("redirect_uri", forceRedirectUri.toString()),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", TestUtil.getRandom32Bytes())))))
                .getContent();

        assertEquals(new ErrorResponse("invalid_request", errorMessage, null), er);
    }

    @ParameterizedTest
    @MethodSource("getFailsValidationUrisAndErrorMessage")
    public void testRedirectUriFailValidationAsDefault(URI forceRedirectUri, String errorMessage) {
        ErrorResponse er = (ErrorResponse) assertThrows(OAuthReponse.JsonPage.class, () ->
                AuthorizationRequest.parser().parse(
                        new MockCredentials.MockClientRegistration() {
                            @Override
                            public @NonNull @lombok.NonNull Collection<URI> getAllowedRedirectUris() {
                                return List.of(forceRedirectUri);
                            }
                        },
                        new Param.MockReader(List.of(
                                new Param("response_type", "code"),
                                new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                                new Param("code_challenge_method", "S256"),
                                new Param("code_challenge", TestUtil.getRandom32Bytes())))))
                .getContent();

        assertEquals(new ErrorResponse("invalid_request", errorMessage, null), er);
    }

    @Test
    public void testRedirectUriSuccessNoHttpLocalhost() {
        URI redirectUri = URI.create("http://localhost/an_endpoint");
        String codeChallenge = TestUtil.getRandom32Bytes();

        AuthorizationRequest request = assertDoesNotThrow(() -> AuthorizationRequest.parser().parse(
                new MockCredentials.MockClientRegistration() {
                    @Override
                    public @NonNull @lombok.NonNull Collection<URI> getAllowedRedirectUris() {
                        return List.of(redirectUri);
                    }
                },
                new Param.MockReader(List.of(
                        new Param("response_type", "code"),
                        new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                        new Param("redirect_uri", redirectUri.toString()),
                        new Param("code_challenge_method", "S256"),
                        new Param("code_challenge", codeChallenge))))).getRequest();

        assertEquals(new AuthorizationRequest.AuthorizationCode(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        true,
                        redirectUri,
                        MockCredentials.DEFAULT_SCOPES,
                        null,
                        null,
                        new PkceInfo(CodeChallengeMethod.S256, codeChallenge)),
                request);
    }
}
