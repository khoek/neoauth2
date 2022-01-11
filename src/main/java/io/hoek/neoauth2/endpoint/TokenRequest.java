package io.hoek.neoauth2.endpoint;

import io.hoek.neoauth2.internal.ParamWriter;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.model.GrantType;
import io.hoek.neoauth2.provider.AccessTokenIssuer;
import io.hoek.neoauth2.provider.AccessTokenOrder;
import io.hoek.neoauth2.provider.AuthorizationCodeOrder;
import io.hoek.neoauth2.provider.RegistrationAuthority;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;

public abstract class TokenRequest {

    private final String clientId;
    private final List<String> scopes;

    private TokenRequest(String clientId, List<String> scopes) {
        this.clientId = clientId;
        this.scopes = scopes;
    }

    public static TokenRequestParser parser() {
        return new TokenRequestParser();
    }

    public String getClientId() {
        return clientId;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public abstract GrantType getGrantType();

    protected abstract ParamWriter.Writable generateAccessGrantedResponseWritable(AccessTokenIssuer issuer, String sub, RegistrationAuthority.ClientInfo client);

    public final Response generateAccessGrantedResponse(AccessTokenIssuer issuer, RegistrationAuthority registrationAuthority, String sub) {
        String body = ParamWriter.writeToJson(
                generateAccessGrantedResponseWritable(issuer, sub, registrationAuthority.lookupClientId(getClientId())));

        return Util.addSecurityCacheControlHeaders(Response.ok())
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(body)
                .build();
    }

    // FIXME How to do accessDenied?

    public static final class AuthorizationCode extends TokenRequest {

        private final AuthorizationCodeOrder code;

        AuthorizationCode(String clientId, List<String> scopes, AuthorizationCodeOrder code) {
            super(clientId, scopes);

            this.code = code;
        }

        @Override
        public GrantType getGrantType() {
            return GrantType.AUTHORIZATION_CODE;
        }

        public AuthorizationCodeOrder getCode() {
            return code;
        }

        @Override
        protected ParamWriter.Writable generateAccessGrantedResponseWritable(AccessTokenIssuer issuer, String sub, RegistrationAuthority.ClientInfo client) {
            return issuer.issueAccessToken(
                    new AccessTokenOrder(sub, client.validateScopesAndGetAudience(getScopes()), getScopes(), client.getAccessTokenLifetimeSeconds(), getClientId(), getCode().getNonce()));
        }
    }
}
