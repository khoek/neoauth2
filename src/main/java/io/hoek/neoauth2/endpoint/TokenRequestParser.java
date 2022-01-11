package io.hoek.neoauth2.endpoint;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.hoek.neoauth2.internal.InvalidRequestException;
import io.hoek.neoauth2.internal.ParamReader;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.model.AuthorizationCodePayload;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.model.GrantType;
import io.hoek.neoauth2.provider.AuthorizationCodeIssuer;
import io.hoek.neoauth2.provider.AuthorizationCodeOrder;
import org.apache.commons.collections4.CollectionUtils;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

public class TokenRequestParser {
    // FIXME REMOVE
    private static final ObjectMapper MAPPER = new ObjectMapper();

    TokenRequestParser() {
    }

    public TokenRequest parse(AuthorizationCodeIssuer verifier, UriInfo uriInfo) throws ReturnErrorResponseException {
        return parse(verifier, uriInfo.getQueryParameters());
    }

    public TokenRequest parse(AuthorizationCodeIssuer verifier, MultivaluedMap<String, String> params) throws ReturnErrorResponseException {
        return parse(verifier, params::get);
    }

    // FIXME We don't actually need the whole `AuthorizationRequest` here? Keep all the parts we need.
    public TokenRequest parse(AuthorizationCodeIssuer verifier, ParamReader params) throws ReturnErrorResponseException {
        try {
            return parseRequest(verifier, params);
        } catch (InvalidRequestException e) {
            throw e.toErrorPageException();
        }
    }

    // FIXME We don't actually need the whole `AuthorizationRequest` here? Keep all the parts we need.
    private TokenRequest parseRequest(AuthorizationCodeIssuer verifier, ParamReader params) throws InvalidRequestException {
        // FIXME perform the necessary verifications of `req` against what we are reading in.

        String strGrantType = Util.maybeExtractSingletonParam(params, "grant_type");

        GrantType grantType = GrantType.AUTHORIZATION_CODE;
        if (strGrantType != null) {
            try {
                // TODO Fix, HACK HACK HACK YUCK
                grantType = MAPPER.readValue(MAPPER.writeValueAsString(strGrantType), GrantType.class);
            } catch (JsonProcessingException e) {
                throw new InvalidRequestException(ErrorResponse.DESC_UNSUPPORTED_GRANT_TYPE, "unsupported response type '" + strGrantType + "'");
            }
        }

        // SPEC NOTE: For now we assume all clients are public, and therefore require this parameter
        // in order to verify a match with the supplied authentication token.
        String clientId = Util.extractSingletonParam(params, "client_id");

        String strScope = Util.maybeExtractSingletonParam(params, "scope");
        List<String> scopes = strScope == null ? null : List.of(strScope.split(" "));

        // TODO Once we implement 'client_crentials'(?) grant note from spec:
        //     *  ensure that the authorization code was issued to the authenticated
        //        confidential or credentialed client

        switch (grantType) {
            case AUTHORIZATION_CODE: {
                return parseAuthorizationCodeRequest(verifier, params, clientId, scopes);
            }
        }

        throw new UnsupportedOperationException();
    }

    private TokenRequest parseAuthorizationCodeRequest(AuthorizationCodeIssuer verifier, ParamReader params, String clientId, List<String> scopes) throws InvalidRequestException {
        String strCode = Util.extractSingletonParam(params, "code");
        String strRedirectUri = Util.maybeExtractSingletonParam(params, "redirect_uri");
        String codeVerifier = Util.maybeExtractSingletonParam(params, "code_verifier");

        AuthorizationCodeOrder code = verifier.readAndVerifyAuthorizationCode(new AuthorizationCodePayload(strCode));
        if (code == null) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_GRANT, "invalid code");
        }

        if (!code.getClientId().equals(clientId)) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_GRANT, "mismatched 'client_id' with authorization code");
        }

        // If a `scope` parameter was provided at this step, make sure it matches with the scopes which were assigned to
        // the previously issued authorization code.
        //
        // TODO Might need to be more flexible once we support a `client_credentials` grant.
        if(scopes != null && !CollectionUtils.isEqualCollection(scopes, code.getScopes())) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "mismatched 'scope' with authorization code");
        }

        URI redirectUri;
        try {
            if (strRedirectUri == null) {
                if (code.isRedirectUriProvided()) {
                    throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'redirect_uri'");
                }
            } else {
                redirectUri = new URI(strRedirectUri);
                if (!Util.doUrisMatch(code.getRedirectUri(), redirectUri)) {
                    throw new InvalidRequestException(ErrorResponse.DESC_INVALID_GRANT,
                            code.isRedirectUriProvided() ?
                                    "mismatched 'redirect_uri' with authorization code" :
                                    "'redirect_uri' does not match registered default");
                }
            }

        } catch (URISyntaxException e) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "malformed 'redirect_uri'");
        }

        if ((codeVerifier != null) && (code.getCodeChallenge() == null)) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'code_challenge' from authorization");
        }

        if ((codeVerifier == null) && (code.getCodeChallenge() != null)) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'code_verifier'");
        }

        if (codeVerifier != null) {
            String localCodeChallenge = code.getCodeChallengeMethod().calculateChallenge(codeVerifier);
            if (!localCodeChallenge.equals(code.getCodeChallenge())) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "code challenge validation failed");
            }
        }

        return new TokenRequest.AuthorizationCode(clientId, code.getScopes(), code);
    }
}
