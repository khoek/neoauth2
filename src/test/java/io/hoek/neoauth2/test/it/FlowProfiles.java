package io.hoek.neoauth2.test.it;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.hoek.neoauth2.endpoint.AuthorizationRequestParser;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.provider.IssuerBundle;
import io.hoek.neoauth2.provider.RegistrationAuthority;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class FlowProfiles {

    public static class StandardPkceFlow implements FlowSimulator.Profile {
        private final SecureRandom random = new SecureRandom();
        private final String codeVerifier = Util.calculateRandomBytesBase64UrlEncodedWithoutPadding(random, 32);
        private final String codeChallenge = Util.calculateSha256Base64UrlEncodedWithoutPadding(codeVerifier);

        private final URI redirectUri;
        private final List<AuthorizationRequestParser.Extension> extensions;

        public StandardPkceFlow(URI redirectUri, AuthorizationRequestParser.Extension... extensions) {
            this(redirectUri, Arrays.asList(extensions));
        }

        public StandardPkceFlow(URI redirectUri, List<AuthorizationRequestParser.Extension> extensions) {
            this.redirectUri = redirectUri;
            this.extensions = extensions;
        }

        public String getCodeVerifier() {
            return codeVerifier;
        }

        public String getCodeChallenge() {
            return codeChallenge;
        }

        @Override
        public IssuerBundle getIssuerBundle() {
            return MockCredentials.DEFAULT_ISSUER_BUNDLE;
        }

        @Override
        public RegistrationAuthority getRegistrationAuthority() {
            return MockCredentials.DEFAULT_REGISTRATION_AUTHORITY;
        }

        @Override
        public String getSub() {
            return MockCredentials.DEFAULT_CLAIM_SUB;
        }

        @Override
        public final void configureAuthorizationRequestParser(AuthorizationRequestParser parser) {
            extensions.forEach(parser::addExtension);
        }

        @Override
        public URI buildEndpointParamsForAuthorization(URI authorizationUri) {
            return UriBuilder.fromUri(authorizationUri).queryParam("response_type", "code")
                    .queryParam("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID)
                    .queryParam("redirect_uri", redirectUri)
                    .queryParam("code_challenge_method", "S256")
                    .queryParam("code_challenge", getCodeChallenge())
                    .build();
        }

        @Override
        public String buildEndpointParamsForToken(String code) {
            return "grant_type=authorization_code"
                    + "&client_id=" + URLEncoder.encode(MockCredentials.DEFAULT_CLAIM_CLIENT_ID, StandardCharsets.UTF_8)
                    + "&redirect_uri=" + URLEncoder.encode(redirectUri.toString(), StandardCharsets.UTF_8)
                    + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                    + "&code_verifier=" + URLEncoder.encode(getCodeVerifier(), StandardCharsets.UTF_8);
        }
    }

    public static JwtClaims assertAccessTokenValidClaims(ObjectNode response) {
        String accessToken = response.get("access_token").asText();

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setVerificationKey(MockCredentials.DEFAULT_SIGNING_KEY_PUBLIC)
                .setRequireJwtId()
                .setExpectedType(true, "at+JWT")
                .setExpectedIssuer(true, MockCredentials.DEFAULT_ISSUER_URI)
                .setExpectedAudience(true, MockCredentials.DEFAULT_AUDIENCE_URI)
                .setExpectedSubject(MockCredentials.DEFAULT_CLAIM_SUB)
                .setRequireSubject()
                .setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, "RS256"))
                .setRequireIssuedAt()
                .setRequireExpirationTime()
                .setRequireNotBefore()
                .build();

        JwtClaims claims = assertDoesNotThrow(() -> consumer.processToClaims(accessToken));

        assertEquals(MockCredentials.DEFAULT_CLAIM_CLIENT_ID, claims.getClaimValueAsString("client_id"));
        assertEquals(String.join(" ", MockCredentials.DEFAULT_SCOPES), claims.getClaimValueAsString("scope"));

        return claims;
    }
}
