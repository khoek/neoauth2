package io.hoek.neoauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.hoek.neoauth2.backend.AuthorizationCodeIssuer;
import io.hoek.neoauth2.backend.AuthorizationCodeOrder;
import io.hoek.neoauth2.internal.InvalidRequestException;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.model.AuthorizationCodePayload;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.model.GrantType;
import org.apache.commons.collections4.CollectionUtils;

import javax.validation.constraints.NotNull;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class TokenRequestParser {

    private final ObjectMapper mapper = new ObjectMapper();

    TokenRequestParser() {
    }

    public TokenRequest parse(AuthorizationCodeIssuer verifier, UriInfo uriInfo) {
        return parse(verifier, uriInfo.getQueryParameters());
    }

    public TokenRequest parse(AuthorizationCodeIssuer verifier, MultivaluedMap<String, String> params) {
        return parse(verifier, ParamReader.from(params::get));
    }

    public TokenRequest parse(AuthorizationCodeIssuer verifier, ParamReader params) {
        try {
            return parseRequest(verifier, params);
        } catch (InvalidRequestException e) {
            throw e.toErrorPageException();
        }
    }

    private @NotNull GrantType parseGrantType(ParamReader params) throws InvalidRequestException {
        String strGrantType = params.maybeExtractSingletonParam("grant_type");

        if (strGrantType == null) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'grant_type'");
        }

        GrantType grantType;
        try {
            grantType = Objects.requireNonNull(mapper.convertValue(strGrantType, GrantType.class));
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException(ErrorResponse.DESC_UNSUPPORTED_GRANT_TYPE, "unsupported grant type '" + strGrantType + "'");
        }

        return grantType;
    }

    private TokenRequest parseRequest(AuthorizationCodeIssuer verifier, ParamReader params) throws InvalidRequestException {
        GrantType grantType = parseGrantType(params);

        // TODO: Once we implement 'client_credentials'(?) grant note from spec:
        //     *  ensure that the authorization code was issued to the authenticated
        //        confidential or credentialed client

        switch (grantType) {
            case AUTHORIZATION_CODE:
                return parseAuthorizationCodeRequest(verifier, params);
            default:
                throw new UnsupportedOperationException();
        }
    }

    private void checkClientId(ParamReader params, AuthorizationCodeOrder order) throws InvalidRequestException {
        // SPEC NOTE: For now we assume all clients are public, and therefore require this parameter
        // in order to verify a match with the supplied authentication token.

        if (!order.getClientId().equals(params.extractSingletonParam("client_id"))) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_GRANT, "mismatched 'client_id' with authorization code");
        }
    }

    private void checkScopes(ParamReader params, AuthorizationCodeOrder order) throws InvalidRequestException {
        String strScope = params.maybeExtractSingletonParam("scope");
        if (strScope == null) {
            return;
        }

        List<String> scopes = Arrays.asList(strScope.split(" "));

        // If a `scope` parameter was provided at this step, make sure it matches with the scopes which were assigned to
        // the previously issued authorization code.
        //
        // TODO: Might need to be more flexible once we support a `client_credentials` grant.
        if (!CollectionUtils.isEqualCollection(scopes, order.getScopes())) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "mismatched 'scope' with authorization code");
        }
    }

    private void checkRedirectUri(ParamReader params, AuthorizationCodeOrder order) throws InvalidRequestException {
        String strRedirectUri = params.maybeExtractSingletonParam("redirect_uri");

        if (strRedirectUri == null) {
            if (order.isRedirectUriProvided()) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'redirect_uri'");
            }

            return;
        }

        try {
            URI redirectUri = new URI(strRedirectUri);
            if (!Util.doUrisMatch(order.getRedirectUri(), redirectUri)) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_GRANT, order.isRedirectUriProvided()
                        ? "mismatched 'redirect_uri' with authorization code"
                        : "'redirect_uri' does not match registered default");
            }
        } catch (URISyntaxException e) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "malformed 'redirect_uri'");
        }
    }

    private void checkPkce(ParamReader params, AuthorizationCodeOrder order) throws InvalidRequestException {
        String codeVerifier = params.maybeExtractSingletonParam("code_verifier");

        if (codeVerifier == null) {
            if (order.getPkceInfo() != null) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'code_verifier'");
            }

            return;
        }

        if (order.getPkceInfo() == null) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'code_challenge' from authorization");
        }

        String localCodeChallenge = order.getPkceInfo().getMethod().calculateChallenge(codeVerifier);
        if (!localCodeChallenge.equals(order.getPkceInfo().getChallenge())) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "code challenge validation failed");
        }
    }

    private TokenRequest parseAuthorizationCodeRequest(AuthorizationCodeIssuer verifier, ParamReader params) throws InvalidRequestException {
        AuthorizationCodePayload code = new AuthorizationCodePayload(params.extractSingletonParam("code"));
        AuthorizationCodeOrder order = verifier.readAndVerifyAuthorizationCode(code);
        if (order == null) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_GRANT, "invalid code");
        }

        checkClientId(params, order);
        checkScopes(params, order);
        checkRedirectUri(params, order);
        checkPkce(params, order);

        return new TokenRequest.AuthorizationCode(order);
    }
}
