package io.hoek.neoauth2.test.it;

import io.hoek.neoauth2.provider.IssuerBundle;
import io.hoek.neoauth2.provider.RegistrationAuthority;
import io.hoek.neoauth2.provider.builtin.RandomAuthorizationCodeIssuer;
import io.hoek.neoauth2.provider.builtin.Rfc9068AccessTokenIssuer;
import io.hoek.neoauth2.provider.builtin.SimpleMemoryDataStore;
import lombok.NonNull;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.List;

public class MockCredentials {
    public static final String DEFAULT_ISSUER_URI = "https://api.example.com/auth";
    public static final String DEFAULT_AUDIENCE_URI = "https://api.example.com/v1";
    public static final String DEFAULT_KEY_ID = "k1";
    public static final List<String> DEFAULT_SCOPES = List.of("ascope", "anotherscope");
    public static final List<URI> DEFAULT_ALLOWED_REDIRECT_URIS = List.of(
            URI.create("https://example.com/callback"),
            URI.create("http://127.0.0.1:9090/redirect_endpoint"));
    public static final String DEFAULT_CLAIM_CLIENT_ID = "robert";
    public static final String DEFAULT_CLAIM_SUB = "steve";
    public static final RSAPrivateCrtKey DEFAULT_SIGNING_KEY_PRIVATE;
    public static final RSAPublicKey DEFAULT_SIGNING_KEY_PUBLIC;


    static {
        try {
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            DEFAULT_SIGNING_KEY_PRIVATE = (RSAPrivateCrtKey) keyPair.getPrivate();
            DEFAULT_SIGNING_KEY_PUBLIC = (RSAPublicKey) keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static final IssuerBundle DEFAULT_ISSUER_BUNDLE = new IssuerBundle(
            new RandomAuthorizationCodeIssuer(new SimpleMemoryDataStore(true)),
            new Rfc9068AccessTokenIssuer(DEFAULT_ISSUER_URI, List.of(DEFAULT_AUDIENCE_URI), DEFAULT_KEY_ID, DEFAULT_SIGNING_KEY_PRIVATE));

    public static final RegistrationAuthority DEFAULT_REGISTRATION_AUTHORITY = clientId -> new MockClientInfo();

    public static class MockClientInfo implements RegistrationAuthority.ClientInfo {

        @Override
        public List<String> getDefaultScopes() {
            return DEFAULT_SCOPES;
        }

        @Override
        public @NonNull Collection<URI> getAllowedRedirectUris() {
            return DEFAULT_ALLOWED_REDIRECT_URIS;
        }

        @Override
        public @NonNull String validateScopesAndGetAudience(List<String> scopes) {
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
