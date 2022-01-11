package io.hoek.neoauth2.endpoint;

import io.hoek.neoauth2.internal.ParamWriter;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.model.CodeChallengeMethod;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.model.ResponseType;
import io.hoek.neoauth2.provider.AccessTokenOrder;
import io.hoek.neoauth2.provider.AuthorizationCodeOrder;
import io.hoek.neoauth2.provider.IssuerBundle;
import io.hoek.neoauth2.provider.RegistrationAuthority;

import javax.ws.rs.core.Response;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

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

    protected abstract ParamWriter.Writable generateAccessGrantedResponseWritable(IssuerBundle bundle, String sub, RegistrationAuthority.ClientInfo client);

    public final Response generateAccessDeniedResponse() throws ReturnErrorResponseException {
        throw new ReturnErrorResponseException.Redirect(redirectUri, new ErrorResponse(ErrorResponse.DESC_ACCESS_DENIED, "resource owner denied access", state));
    }

    public final Response generateAccessGrantedResponse(IssuerBundle bundle, RegistrationAuthority registrationAuthority, String sub) {
        URI location = ParamWriter.writeToUriWithState(getRedirectUri(), state,
                generateAccessGrantedResponseWritable(bundle, sub, registrationAuthority.lookupClientId(getClientId())));

        return Util.addSecurityCacheControlHeaders(Response.status(Response.Status.FOUND))
                .header("Location", location)
                .build();
    }

    public static final class Implicit extends AuthorizationRequest {

        Implicit(String clientId, boolean redirectUriProvided, URI redirectUri, List<String> scopes, String state, String nonce) {
            super(clientId, redirectUriProvided, redirectUri, scopes, state, nonce);
        }

        @Override
        public ResponseType getResponseType() {
            return ResponseType.IMPLICIT;
        }

        @Override
        protected ParamWriter.Writable generateAccessGrantedResponseWritable(IssuerBundle bundle, String sub, RegistrationAuthority.ClientInfo client) {
            return bundle.issueAccessToken(
                    new AccessTokenOrder(sub, client.validateScopesAndGetAudience(getScopes()), getScopes(), client.getAccessTokenLifetimeSeconds(), getClientId(), nonce));
        }
    }

    public static final class AuthorizationCode extends AuthorizationRequest {

        final String codeChallenge; // Not exposed
        private final CodeChallengeMethod codeChallengeMethod;

        AuthorizationCode(String clientId, boolean redirectUriProvided, URI redirectUri, List<String> scopes, String state, String nonce,
                          CodeChallengeMethod codeChallengeMethod, String codeChallenge) {
            super(clientId, redirectUriProvided, redirectUri, scopes, state, nonce);

            this.codeChallengeMethod = codeChallengeMethod;
            this.codeChallenge = codeChallenge;
        }

        @Override
        public ResponseType getResponseType() {
            return ResponseType.AUTHORIZATION_CODE;
        }

        public CodeChallengeMethod getCodeChallengeMethod() {
            return codeChallengeMethod;
        }

        @Override
        protected ParamWriter.Writable generateAccessGrantedResponseWritable(IssuerBundle bundle, String sub, RegistrationAuthority.ClientInfo client) {
            return bundle.issueAuthorizationCode(
                    new AuthorizationCodeOrder(sub, getClientId(), getScopes(), wasRedirectUriProvided(), getRedirectUri(), getCodeChallengeMethod(), codeChallenge, nonce),
                    Instant.now().plus(Duration.ofSeconds(client.getAuthorizationCodeLifetimeSeconds())));
        }
    }
}
