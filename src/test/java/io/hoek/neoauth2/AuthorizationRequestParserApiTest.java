package io.hoek.neoauth2;

import io.hoek.neoauth2.extension.OAuth21SpecViolation;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.model.CodeChallengeMethod;
import io.hoek.neoauth2.model.PkceInfo;
import io.hoek.neoauth2.test.MockCredentials;
import io.hoek.neoauth2.test.TestUtil;
import org.jboss.resteasy.spi.ResteasyUriInfo;
import org.junit.jupiter.api.Test;

import javax.ws.rs.core.*;
import java.net.URI;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class AuthorizationRequestParserApiTest {

    @Test
    public void testEnforceSealedExtensionClasses() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                AuthorizationRequest.parser().addExtension(new MySuperDuperSpecialExtension()));

        assertEquals(ex.getMessage(), "Custom extensions are not supported! (" + MySuperDuperSpecialExtension.class + ")");
    }

    @Test
    public void testNoDuplciateExtensions() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                AuthorizationRequest.parser()
                        .addExtension(OAuth21SpecViolation.allowImplicit())
                        .addExtension(OAuth21SpecViolation.allowImplicit()));

        assertEquals(ex.getMessage(), "duplicate extension: " + OAuth21SpecViolation.AllowImplicit.class);
    }

    private static class MySuperDuperSpecialExtension extends AuthorizationRequestParser.Extension {
        @Override
        public String toString() {
            return "Super Duper Special Extension";
        }
    }

    @Test
    public void testParseUriInfo() {
        String codeChallenge = TestUtil.getRandom32Bytes();

        AuthorizationRequest request = assertDoesNotThrow(() -> AuthorizationRequest.parser()
                .parse(MockCredentials.DEFAULT_REGISTRATION_AUTHORITY, new ResteasyUriInfo(
                        UriBuilder.fromUri("https://auth.example.com/authorization")
                                .queryParam("response_type", "code")
                                .queryParam("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID)
                                .queryParam("redirect_uri", MockCredentials.DEFAULT_REDIRECT_URI.toString())
                                .queryParam("code_challenge_method", "S256")
                                .queryParam("code_challenge",  codeChallenge)
                                .build())));

        assertEquals(new AuthorizationRequest.AuthorizationCode(
                        MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                        true,
                        MockCredentials.DEFAULT_REDIRECT_URI,
                        MockCredentials.DEFAULT_SCOPES,
                        null,
                        null,
                        new PkceInfo(CodeChallengeMethod.S256, codeChallenge)),
                request);
    }
}
