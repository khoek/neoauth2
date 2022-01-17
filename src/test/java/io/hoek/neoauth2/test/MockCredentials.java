package io.hoek.neoauth2.test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.hoek.neoauth2.backend.AuthorizationCodeOrder;
import io.hoek.neoauth2.backend.IssuerBundle;
import io.hoek.neoauth2.backend.RegistrationAuthority;
import io.hoek.neoauth2.backend.builtin.RandomAuthorizationCodeIssuer;
import io.hoek.neoauth2.backend.builtin.Rfc9068AccessTokenIssuer;
import io.hoek.neoauth2.backend.builtin.SimpleMemoryDataStore;
import io.hoek.neoauth2.model.CodeChallengeMethod;
import io.hoek.neoauth2.model.PkceInfo;
import lombok.SneakyThrows;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import javax.validation.constraints.NotNull;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class MockCredentials {
    public static final String DEFAULT_ISSUER_URI = "https://api.example.com/auth";
    public static final String DEFAULT_AUDIENCE_URI = "https://api.example.com/v1";
    public static final String DEFAULT_KEY_ID = "k1";
    public static final List<String> DEFAULT_SCOPES = List.of("ascope", "anotherscope");
    public static final URI DEFAULT_REDIRECT_URI = URI.create("https://example.com/redirect_endpoint");
    public static final List<URI> DEFAULT_ALLOWED_REDIRECT_URIS = List.of(
            DEFAULT_REDIRECT_URI,
            URI.create("https://example.com/callback"),
            URI.create("http://127.0.0.1:9090/redirect_endpoint"));
    public static final String DEFAULT_CLAIM_CLIENT_ID = "robert";
    public static final String DEFAULT_CLAIM_SUB = "steve";
    public static final RSAPrivateCrtKey DEFAULT_SIGNING_KEY_PRIVATE;
    public static final RSAPublicKey DEFAULT_SIGNING_KEY_PUBLIC;
    public static final IssuerBundle<?, ?> DEFAULT_ISSUER_BUNDLE;
    public static final RegistrationAuthority DEFAULT_REGISTRATION_AUTHORITY = clientId -> new MockClientInfo();

    static {
        try {
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            DEFAULT_SIGNING_KEY_PRIVATE = (RSAPrivateCrtKey) keyPair.getPrivate();
            DEFAULT_SIGNING_KEY_PUBLIC = (RSAPublicKey) keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        DEFAULT_ISSUER_BUNDLE = new IssuerBundle<>(
                new RandomAuthorizationCodeIssuer(new SimpleMemoryDataStore(true)),
                new Rfc9068AccessTokenIssuer(DEFAULT_ISSUER_URI, List.of(DEFAULT_AUDIENCE_URI), DEFAULT_KEY_ID, DEFAULT_SIGNING_KEY_PRIVATE));
    }

    public static AuthorizationCodeOrder getDefaultAuthorizationCodeOrder(String codeVerifier) {
        return new AuthorizationCodeOrder(
                MockCredentials.DEFAULT_CLAIM_SUB,
                MockCredentials.DEFAULT_CLAIM_CLIENT_ID,
                MockCredentials.DEFAULT_SCOPES,
                true,
                MockCredentials.DEFAULT_REDIRECT_URI,
                new PkceInfo(CodeChallengeMethod.S256, CodeChallengeMethod.S256.calculateChallenge(codeVerifier)),
                TestUtil.getRandom32Bytes()
        );
    }

    public static JwtClaims assertAccessTokenClaimsValidForDefaultIssuer(String raw) {
        return assertAccessTokenClaimsValidForDefaultIssuer(raw, DEFAULT_SCOPES);
    }

    @SneakyThrows(JsonProcessingException.class)
    public static JwtClaims assertAccessTokenClaimsValidForDefaultIssuer(String raw, List<String> testScopes) {
        return assertAccessTokenClaimsValidForDefaultIssuer(new ObjectMapper().readValue(raw, ObjectNode.class), testScopes);
    }

    public static JwtClaims assertAccessTokenClaimsValidForDefaultIssuer(ObjectNode response) {
        return assertAccessTokenClaimsValidForDefaultIssuer(response, DEFAULT_SCOPES);
    }

    public static JwtClaims assertAccessTokenClaimsValidForDefaultIssuer(ObjectNode response, List<String> testScopes) {
        String accessToken = response.get("access_token").asText();

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setVerificationKey(DEFAULT_SIGNING_KEY_PUBLIC)
                .setRequireJwtId()
                .setExpectedType(true, "at+JWT")
                .setExpectedIssuer(true, DEFAULT_ISSUER_URI)
                .setExpectedAudience(true, DEFAULT_AUDIENCE_URI)
                .setExpectedSubject(DEFAULT_CLAIM_SUB)
                .setRequireSubject()
                .setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, "RS256"))
                .setRequireIssuedAt()
                .setRequireExpirationTime()
                .setRequireNotBefore()
                .build();

        JwtClaims claims = assertDoesNotThrow(() -> consumer.processToClaims(accessToken));

        assertEquals(DEFAULT_CLAIM_CLIENT_ID, claims.getClaimValueAsString("client_id"));
        assertEquals(String.join(" ", testScopes), claims.getClaimValueAsString("scope"));

        assertEquals("Bearer", response.get("token_type").asText());
        assertEquals(DEFAULT_REGISTRATION_AUTHORITY.lookupClientId(DEFAULT_CLAIM_CLIENT_ID)
                .getAccessTokenLifetimeSeconds(), response.get("expires_in").asLong());
        assertEquals(String.join(" ", testScopes), response.get("scope").asText());

        return claims;
    }

    public static class MockClientInfo implements RegistrationAuthority.ClientInfo {

        @Override
        public List<String> getDefaultScopes() {
            return DEFAULT_SCOPES;
        }

        @Override
        public @NotNull Collection<URI> getAllowedRedirectUris() {
            return DEFAULT_ALLOWED_REDIRECT_URIS;
        }

        @Override
        public @NotNull String validateScopesAndGetAudience(List<String> scopes) {
            return DEFAULT_AUDIENCE_URI;
        }

        @Override
        public long getAuthorizationCodeLifetimeSeconds() {
            return 5 * 60;
        }

        @Override
        public long getAccessTokenLifetimeSeconds() {
            return 24 * 60 * 60;
        }
    }
}
