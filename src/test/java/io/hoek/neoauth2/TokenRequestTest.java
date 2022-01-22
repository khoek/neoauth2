package io.hoek.neoauth2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.hoek.neoauth2.backend.UserAuthorization;
import io.hoek.neoauth2.backend.TokenSpec;
import io.hoek.neoauth2.model.CodeChallengeMethod;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.model.PkceInfo;
import io.hoek.neoauth2.test.MockCredentials;
import io.hoek.neoauth2.test.TestUtil;
import org.junit.jupiter.api.Test;

import javax.validation.constraints.NotNull;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TokenRequestTest {

    @Test
    public void testSuccessGenerateAccessGrantedResponse() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        Response response = new TokenRequestGranter(
                MockCredentials.DEFAULT_ISSUER_BUNDLE,
                MockCredentials.DEFAULT_CLIENT_REGISTRATION,
                new TokenRequest.AuthorizationCode(MockCredentials.getDefaultAuthorizationCodeOrder(codeVerifier))
        ).grant().getResponse();

        MockCredentials.assertAccessTokenClaimsValidForDefaultIssuer(response.getEntity().toString());
        assertEquals("no-store", response.getHeaderString("Cache-Control"));
    }

    @Test
    public void testCustomScopeValidationAccept() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        Response response = new TokenRequestGranter(
                MockCredentials.DEFAULT_ISSUER_BUNDLE,
                new MockCredentials.MockClientRegistration() {
                    @Override
                    public @NotNull String validateScopesAndGetAudience(List<String> scopes) {
                        if (!Set.of("31337Haxxor77scopeA", "31337Haxxor77scopeB").containsAll(scopes)) {
                            return null;
                        }

                        return MockCredentials.DEFAULT_AUDIENCE_URI;
                    }
                },
                new TokenRequest.AuthorizationCode(new UserAuthorization(
                new TokenSpec(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        List.of("31337Haxxor77scopeA"),
                        Map.of(
                                "sub", MockCredentials.DEFAULT_CLAIM_SUB,
                                "aud", MockCredentials.DEFAULT_AUDIENCE_URI,
                                "nonce", TestUtil.getRandom32Bytes())),
                true,
                MockCredentials.DEFAULT_REDIRECT_URI,
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier))
        ))).grant().getResponse();

        assertEquals("no-store", response.getHeaderString("Cache-Control"));
        MockCredentials.assertAccessTokenClaimsValidForDefaultIssuer(response.getEntity()
                .toString(), List.of("31337Haxxor77scopeA"));
    }

    @Test
    public void testCustomScopeValidationReject() throws JsonProcessingException {
        String codeVerifier = TestUtil.getRandom32Bytes();
        Response response = new TokenRequestGranter(
                MockCredentials.DEFAULT_ISSUER_BUNDLE,
                new MockCredentials.MockClientRegistration() {
                    @Override
                    public @NotNull String validateScopesAndGetAudience(List<String> scopes) {
                        if (!Set.of("31337Haxxor77scopeA", "31337Haxxor77scopeB").containsAll(scopes)) {
                            return null;
                        }

                        return MockCredentials.DEFAULT_AUDIENCE_URI;
                    }
                },
                new TokenRequest.AuthorizationCode(new UserAuthorization(
                new TokenSpec(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        List.of("anotherscope"),
                        Map.of("sub", MockCredentials.DEFAULT_CLAIM_SUB, "nonce", TestUtil.getRandom32Bytes())),
                true,
                MockCredentials.DEFAULT_REDIRECT_URI,
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier))
        ))).grant().getResponse();

        assertEquals("no-store", response.getHeaderString("Cache-Control"));

        ErrorResponse er = new ObjectMapper().readValue(response.getEntity().toString(), ErrorResponse.class);
        assertEquals(new ErrorResponse("invalid_scope", "scopes not authorized", null), er);
    }
}
