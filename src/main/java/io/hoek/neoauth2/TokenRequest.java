package io.hoek.neoauth2;

import io.hoek.neoauth2.backend.AccessTokenIssuer;
import io.hoek.neoauth2.backend.AccessTokenOrder;
import io.hoek.neoauth2.backend.AuthorizationCodeOrder;
import io.hoek.neoauth2.backend.RegistrationAuthority;
import io.hoek.neoauth2.exception.WritableWebApplicationException;
import io.hoek.neoauth2.exception.WritableWebApplicationException.JsonPage;
import io.hoek.neoauth2.internal.InvalidRequestException;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.model.GrantType;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import javax.ws.rs.core.Response;
import java.util.List;

@ToString
@EqualsAndHashCode
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

    protected abstract ParamWriter.Writable generateAccessGrantedResponseWritable(AccessTokenIssuer issuer, String sub, RegistrationAuthority.ClientInfo client) throws InvalidRequestException;

    public final WritableWebApplicationException.JsonPage generateAccessGranted(AccessTokenIssuer issuer, RegistrationAuthority registrationAuthority) {
        return generateAccessGranted(issuer, registrationAuthority, null);
    }

    public final WritableWebApplicationException.JsonPage generateAccessGranted(AccessTokenIssuer issuer, RegistrationAuthority registrationAuthority, String sub) {
        try {
            return new WritableWebApplicationException.JsonPage(Response.Status.OK,
                    generateAccessGrantedResponseWritable(issuer, sub, registrationAuthority.lookupClientId(getClientId())));
        } catch (InvalidRequestException ex) {
            return ex.toErrorPageException();
        }
    }

    // FIXME How to do accessDenied?

    @ToString(callSuper = true)
    @EqualsAndHashCode(callSuper = true)
    public static final class AuthorizationCode extends TokenRequest {

        private final AuthorizationCodeOrder code;

        AuthorizationCode(AuthorizationCodeOrder code) {
            super(code.getClientId(), code.getScopes());

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
        protected ParamWriter.Writable generateAccessGrantedResponseWritable(AccessTokenIssuer issuer, String sub, RegistrationAuthority.ClientInfo client) throws InvalidRequestException {
            String aud = client.validateScopesAndGetAudience(getScopes());
            if (aud == null) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_SCOPE, "scopes not authorized");
            }

            if (sub != null && getCode().getSub() != null && !sub.equals(getCode().getSub())) {
                throw new IllegalArgumentException("mismatched sub: argument='" + sub + "' vs codeOrder='" + getCode().getSub() + "'");
            }

            return issuer.issueAccessToken(
                    new AccessTokenOrder(getCode().getSub(), aud, getScopes(), client.getAccessTokenLifetimeSeconds(), getClientId(), getCode().getNonce()));
        }
    }
}
