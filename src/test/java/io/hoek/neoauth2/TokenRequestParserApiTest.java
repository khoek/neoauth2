package io.hoek.neoauth2;

import io.hoek.neoauth2.backend.UserAuthorization;
import io.hoek.neoauth2.backend.TokenSpec;
import io.hoek.neoauth2.model.CodeChallengeMethod;
import io.hoek.neoauth2.model.PkceInfo;
import io.hoek.neoauth2.test.MockCredentials;
import io.hoek.neoauth2.test.TestUtil;
import org.jboss.resteasy.spi.ResteasyUriInfo;
import org.junit.jupiter.api.Test;

import javax.ws.rs.core.UriBuilder;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TokenRequestParserApiTest {

    @Test
    public void testParseUriInfo() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        String codeChallenge = CodeChallengeMethod.S256.calculateChallenge(codeVerifier);
        String nonce = TestUtil.getRandom32Bytes();

        UserAuthorization order = new UserAuthorization(
                new TokenSpec(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        MockCredentials.DEFAULT_SCOPES,
                        Map.of("sub", MockCredentials.DEFAULT_CLAIM_SUB, "nonce", nonce)),
                true,
                MockCredentials.DEFAULT_REDIRECT_URI,
                new PkceInfo(CodeChallengeMethod.S256, codeChallenge)
        );

        TokenRequest response = assertDoesNotThrow(() ->
                TokenRequest.parser()
                        .parse(TokenRequestParserFlowAuthorizationCodeTest.getMockIssuerBundle(order),
                                new MockCredentials.MockClientRegistration(),
                                new ResteasyUriInfo(
                                        UriBuilder.fromUri("https://auth.example.com/authorization")
                                                .queryParam("grant_type", "authorization_code")
                                                .queryParam("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID)
                                                .queryParam("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString())
                                                .queryParam("code", TokenRequestParserFlowAuthorizationCodeTest.MockAuthorizationCodeVerifier.MAGIC_CODE)
                                                .queryParam("code_verifier", codeVerifier)
                                                .build())
                        )).getRequest();

        assertEquals(new TokenRequest.AuthorizationCode(order), response);
    }
}
