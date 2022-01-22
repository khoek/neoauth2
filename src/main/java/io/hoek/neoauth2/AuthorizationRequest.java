package io.hoek.neoauth2;

import io.hoek.neoauth2.backend.*;
import io.hoek.neoauth2.internal.InvalidRequestException;
import io.hoek.neoauth2.internal.ParamWriter;
import io.hoek.neoauth2.model.CodeChallengeMethod;
import io.hoek.neoauth2.model.PkceInfo;
import io.hoek.neoauth2.model.ResponseType;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

@ToString
@EqualsAndHashCode
public abstract class AuthorizationRequest {

    final String state; // Not exposed
    final String nonce; // Not exposed
    private final String clientId;
    private final boolean redirectUriProvided;
    private final URI redirectUri;
    private List<String> scopes;

    private AuthorizationRequest(String clientId, boolean redirectUriProvided, URI redirectUri, List<String> scopes, String state, String nonce) {
        this.clientId = clientId;
        this.redirectUriProvided = redirectUriProvided;
        this.redirectUri = redirectUri;
        this.scopes = scopes;
        this.state = state;
        this.nonce = nonce;
    }

    public static AuthorizationRequestParser parser() {
        return new AuthorizationRequestParser();
    }

    public String getClientId() {
        return clientId;
    }

    public boolean wasRedirectUriProvided() {
        return redirectUriProvided;
    }

    public URI getRedirectUri() {
        return redirectUri;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public void setScopes(List<String> scopes) {
        this.scopes = List.copyOf(scopes);
    }

    public abstract ResponseType getResponseType();

    abstract ParamWriter.Writable generateAccessGrantedWritable(IssuerBundle bundle, ClientRegistration client, UserRegistration user) throws InvalidRequestException;

    @ToString(callSuper = true)
    @EqualsAndHashCode(callSuper = true)
    public static final class Implicit extends AuthorizationRequest {

        Implicit(String clientId, boolean redirectUriProvided, URI redirectUri, List<String> scopes, String state, String nonce) {
            super(clientId, redirectUriProvided, redirectUri, scopes, state, nonce);
        }

        @Override
        public ResponseType getResponseType() {
            return ResponseType.IMPLICIT;
        }

        @Override
        protected ParamWriter.Writable generateAccessGrantedWritable(IssuerBundle bundle, ClientRegistration client, UserRegistration user) throws InvalidRequestException {
            return bundle.issueAccessToken(new AccessTokenOrder(TokenSpec.from(client, user, getClientId(), getScopes(), nonce), client.getAccessTokenLifetimeSeconds()));
        }
    }

    @ToString(callSuper = true)
    @EqualsAndHashCode(callSuper = true)
    public static final class AuthorizationCode extends AuthorizationRequest {

        private final PkceInfo pkceInfo; // Not exposed

        AuthorizationCode(String clientId, boolean redirectUriProvided, URI redirectUri, List<String> scopes, String state, String nonce, PkceInfo pkceInfo) {
            super(clientId, redirectUriProvided, redirectUri, scopes, state, nonce);

            this.pkceInfo = pkceInfo;
        }

        @Override
        public ResponseType getResponseType() {
            return ResponseType.AUTHORIZATION_CODE;
        }

        public CodeChallengeMethod getCodeChallengeMethod() {
            return pkceInfo == null ? null : pkceInfo.getMethod();
        }

        @Override
        protected ParamWriter.Writable generateAccessGrantedWritable(IssuerBundle bundle, ClientRegistration client, UserRegistration user)  throws InvalidRequestException {
            return bundle.issueAuthorizationCode(
                    new UserAuthorization(TokenSpec.from(client, user, getClientId(), getScopes(), nonce), wasRedirectUriProvided(), getRedirectUri(), pkceInfo),
                    Instant.now().plus(Duration.ofSeconds(client.getAuthorizationCodeLifetimeSeconds())));
        }
    }
}
