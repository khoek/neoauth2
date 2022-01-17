package io.hoek.neoauth2;

import io.hoek.neoauth2.backend.AuthorizationCodeOrder;
import io.hoek.neoauth2.model.CodeChallengeMethod;
import io.hoek.neoauth2.model.PkceInfo;
import io.hoek.neoauth2.test.MockCredentials;
import io.hoek.neoauth2.test.TestUtil;
import org.jboss.resteasy.spi.ResteasyUriInfo;
import org.junit.jupiter.api.Test;

import javax.ws.rs.core.UriBuilder;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TokenRequestParserApiTest {

    @Test
    public void testParseUriInfo() {
        String codeVerifier = TestUtil.getRandom32Bytes();
        String codeChallenge = CodeChallengeMethod.S256.calculateChallenge(codeVerifier);
        String nonce = TestUtil.getRandom32Bytes();

        AuthorizationCodeOrder order = new AuthorizationCodeOrder(
                MockCredentials.DEFAULT_CLAIM_SUB,
                MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                MockCredentials.DEFAULT_SCOPES,
                true,
                MockCredentials.DEFAULT_REDIRECT_URI,
                new PkceInfo(CodeChallengeMethod.S256, codeChallenge),
                nonce
        );

        TokenRequest response = assertDoesNotThrow(() ->
                TokenRequest.parser()
                        .parse(new TokenRequestParserFlowAuthorizationCodeTest.MockAuthorizationCodeVerifier(order),
                                new ResteasyUriInfo(
                                        UriBuilder.fromUri("https://auth.example.com/authorization")
                                                .queryParam("grant_type", "authorization_code")
                                                .queryParam("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID)
                                                .queryParam("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString())
                                                .queryParam("code", TokenRequestParserFlowAuthorizationCodeTest.MockAuthorizationCodeVerifier.MAGIC_CODE)
                                                .queryParam("code_verifier", codeVerifier)
                                                .build())
                        ));

        assertEquals(new TokenRequest.AuthorizationCode(order), response);
    }
}
