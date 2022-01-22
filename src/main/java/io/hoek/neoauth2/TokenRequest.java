package io.hoek.neoauth2;

import io.hoek.neoauth2.backend.*;
import io.hoek.neoauth2.internal.InvalidRequestException;
import io.hoek.neoauth2.internal.ParamWriter;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.model.GrantType;
import lombok.EqualsAndHashCode;
import lombok.ToString;

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

    abstract ParamWriter.Writable generateAccessGrantedWritable(AccessTokenIssuer issuer, ClientRegistration client) throws InvalidRequestException;

    // FIXME How to do accessDenied?

    @ToString(callSuper = true)
    @EqualsAndHashCode(callSuper = true)
    public static final class AuthorizationCode extends TokenRequest {

        private final UserAuthorization code;

        AuthorizationCode(UserAuthorization code) {
            super(code.getSpec().getClientId(), code.getSpec().getScopes());

            this.code = code;
        }

        @Override
        public GrantType getGrantType() {
            return GrantType.AUTHORIZATION_CODE;
        }

        public UserAuthorization getCode() {
            return code;
        }

        @Override
        protected ParamWriter.Writable generateAccessGrantedWritable(AccessTokenIssuer issuer, ClientRegistration client) throws InvalidRequestException {
            String aud = client.validateScopesAndGetAudience(getScopes());
            if (aud == null) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_SCOPE, "scopes not authorized");
            }

            // FIXME delete?
            //            if (sub != null && !sub.equals(getCode().getSub())) {
            //                throw new IllegalArgumentException("mismatched sub: argument='" + sub + "' vs codeOrder='" + getCode().getSub() + "'");
            //            }
            //
            //            if (customClaims != null && !CollectionUtils.isEqualCollection(customClaims.entrySet(), getCode().getCustomClaims().entrySet())) {
            //                throw new IllegalArgumentException("mismatched customClaims: argument='" + customClaims + "' vs codeOrder='" + getCode().getCustomClaims() + "'");
            //            }

            return issuer.issueAccessToken(new AccessTokenOrder(getCode().getSpec(), client.getAccessTokenLifetimeSeconds()));
        }
    }

    @ToString(callSuper = true)
    @EqualsAndHashCode(callSuper = true)
    public static final class ClientCredentials extends TokenRequest {

        ClientCredentials(String clientId, List<String> scopes) {
            super(clientId, scopes);
        }

        @Override
        public GrantType getGrantType() {
            return GrantType.CLIENT_CREDENTIALS;
        }

        @Override
        protected ParamWriter.Writable generateAccessGrantedWritable(AccessTokenIssuer issuer, ClientRegistration client) throws InvalidRequestException {
            String aud = client.validateScopesAndGetAudience(getScopes());
            if (aud == null) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_SCOPE, "scopes not authorized");
            }

            if(!(client instanceof UserRegistration)) {
                throw new IllegalArgumentException("provided ClientRegistration does not implement UserRegistration: 'client_credentials' grant disabled");
            }

            return issuer.issueAccessToken(new AccessTokenOrder(TokenSpec.from(
                    client,
                    (UserRegistration) client,
                    getClientId(),
                    getScopes(),
                    null), client.getAccessTokenLifetimeSeconds()));
        }
    }
}
