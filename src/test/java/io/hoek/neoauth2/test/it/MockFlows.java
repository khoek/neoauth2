package io.hoek.neoauth2.test.it;

import io.hoek.neoauth2.backend.IssuerBundle;
import io.hoek.neoauth2.backend.RegistrationAuthority;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.test.MockCredentials;
import io.hoek.neoauth2.test.Param;
import lombok.NonNull;

import java.net.URI;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class MockFlows {

    public static abstract class MockAuthorizationCodeFlowBase<R> extends Flows.AuthorizationCode<R> {
        private final SecureRandom random = new SecureRandom();
        private final String codeVerifier = Util.generateRandomBytesBase64UrlEncodedWithoutPadding(random, 32);
        private final String codeChallenge = Util.calculateSha256Base64UrlEncodedWithoutPadding(codeVerifier);

        private final URI redirectUri;

        public MockAuthorizationCodeFlowBase(URI redirectUri) {
            this.redirectUri = redirectUri;
        }

        public String getCodeVerifier() {
            return codeVerifier;
        }

        public String getCodeChallenge() {
            return codeChallenge;
        }

        @Override
        public IssuerBundle<?, ?> getIssuerBundle() {
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
        public Collection<Param> getAuthorizationEndpointParams() {
            return Set.of(new Param("response_type", "code"),
                    new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                    new Param("redirect_uri", redirectUri.toString()),
                    new Param("code_challenge_method", "S256"),
                    new Param("code_challenge", getCodeChallenge()));
        }

        protected Collection<Param> getTokenEndpointParams(String code) {
            return Set.of(new Param("grant_type", "authorization_code"),
                    new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                    new Param("redirect_uri", redirectUri.toString()),
                    new Param("code", code),
                    new Param("code_verifier", getCodeVerifier()));
        }
    }

    public static class StandardMockAuthorizationCodeFlow extends MockAuthorizationCodeFlowBase<Flows.TokenEndpointResponse> {

        public StandardMockAuthorizationCodeFlow(URI redirectUri) {
            super(redirectUri);
        }

        @Override
        public Flows.TokenEndpointResponse completeFlow(Flows.TokenEndpoint endpoint, String code) {
            return endpoint.performRequest(getTokenEndpointParams(code));
        }
    }

    public static abstract class MockImplicitFlow extends Flows.Implicit {

        private final URI redirectUri;

        public MockImplicitFlow(URI redirectUri) {
            this.redirectUri = redirectUri;
        }

        @Override
        public IssuerBundle<?, ?> getIssuerBundle() {
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
        public @NonNull Collection<Param> getAuthorizationEndpointParams() {
            return Set.of(new Param("response_type", "token"),
                    new Param("client_id", MockCredentials.DEFAULT_CLAIM_CLIENT_ID),
                    new Param("redirect_uri", redirectUri.toString()));
        }
    }
}
