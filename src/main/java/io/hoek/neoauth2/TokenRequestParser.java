package io.hoek.neoauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.hoek.neoauth2.backend.*;
import io.hoek.neoauth2.model.*;
import io.hoek.util.function.Throw;
import io.hoek.neoauth2.internal.InvalidRequestException;
import io.hoek.neoauth2.internal.Util;
import org.apache.commons.collections4.CollectionUtils;

import javax.validation.constraints.NotNull;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

public class TokenRequestParser {

    public static final String PARAM_CLIENT_ID = "client_id";
    public static final String PARAM_GRANT_TYPE = "grant_type";
    public static final String PARAM_REDIRECT_URI = "redirect_uri";
    public static final String PARAM_CODE = "code";
    public static final String PARAM_CODE_VERIFIER = "code_verifier";
    public static final String PARAM_SCOPE = "scope";

    private final ObjectMapper mapper = new ObjectMapper();

    TokenRequestParser() {
    }

    public TokenRequestGranter parse(IssuerBundle bundle, ClientRegistration client, UriInfo uriInfo) {
        return parse(bundle, client, uriInfo.getQueryParameters());
    }

    public TokenRequestGranter parse(IssuerBundle bundle, ClientRegistration client, MultivaluedMap<String, String> params) {
        return parse(bundle, client, ParamReader.from(params::get));
    }

    public TokenRequestGranter parse(IssuerBundle bundle, ClientRegistration client, ParamReader params) {
        return Throw.insteadOf(InvalidRequestException.class,
                () -> new TokenRequestGranter(bundle, client, parseRequest(bundle, client, params)),
                e -> new OAuthReponse.JsonPage(Response.Status.BAD_REQUEST, e.getErrorResponse()));
    }

    private @NotNull GrantType parseGrantType(ParamReader params) throws InvalidRequestException {
        String grantType = Throw.whenNull(params.maybeExtractSingletonParam(PARAM_GRANT_TYPE),
                () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'grant_type'"));

        return Throw.insteadOf(IllegalArgumentException.class,
                () -> Objects.requireNonNull(mapper.convertValue(grantType, GrantType.class)),
                () -> new InvalidRequestException(ErrorResponse.DESC_UNSUPPORTED_GRANT_TYPE, "unsupported grant type '" + grantType + "'"));
    }

    // FIXME client???
    private TokenRequest parseRequest(AuthorizationAuthority verifier, ClientRegistration client, ParamReader params) throws InvalidRequestException {
        GrantType grantType = parseGrantType(params);

        // TODO: Once we implement 'client_credentials'(?) grant note from spec:
        //     *  ensure that the authorization code was issued to the authenticated
        //        confidential or credentialed client

        switch (grantType) {
            case AUTHORIZATION_CODE:
                return new GrantAuthorizationCodeParser().parseRequest(verifier, params);
            case CLIENT_CREDENTIALS:
                return new GrantClientCredentialsParser().parseRequest(params);
            default:
                throw new UnsupportedOperationException();
        }
    }

    private static void checkClientId(ParamReader params, String clientId) throws InvalidRequestException {
        Throw.whenNot(clientId.equals(params.extractSingletonParam(PARAM_CLIENT_ID)),
                () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_GRANT, "mismatched 'client_id' with authorization code"));
    }

    private static void checkScopes(ParamReader params, Collection<String> authorizedScopes) throws InvalidRequestException {
        Optional<List<String>> scopes = Optional.ofNullable(params.maybeExtractSingletonParam(PARAM_SCOPE))
                .map(str -> Arrays.asList(str.split(" ")));
        if (scopes.isEmpty()) {
            return;
        }

        // If a `scope` parameter was provided at this step, make sure it is a subset of the scopes which were
        // assigned to the previously issued authorization code.
        Throw.whenNot(CollectionUtils.isEqualCollection(scopes.get(), authorizedScopes), () ->
                new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "requesting a scope not originally authorized"));
    }

    private static class GrantAuthorizationCodeParser {

        private GrantAuthorizationCodeParser() {
        }

        private static void checkRedirectUri(ParamReader params, boolean oldRedirectUriProvided, URI oldRedirectUri) throws InvalidRequestException {
            String strRedirectUri = params.maybeExtractSingletonParam(PARAM_REDIRECT_URI);
            if (strRedirectUri == null) {
                Throw.when(oldRedirectUriProvided,
                        () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'redirect_uri'"));

                return;
            }

            URI newRedirectUri = Throw.insteadOf(URISyntaxException.class,
                    () -> new URI(strRedirectUri),
                    () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "malformed 'redirect_uri'"));
            Throw.whenNot(Util.doUrisMatch(newRedirectUri, oldRedirectUri),
                    () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_GRANT, oldRedirectUriProvided
                            ? "mismatched 'redirect_uri' with authorization code"
                            : "'redirect_uri' does not match registered default"));
        }

        private static void checkPkce(ParamReader params, PkceInfo pkceInfo) throws InvalidRequestException {
            String codeVerifier = params.maybeExtractSingletonParam(PARAM_CODE_VERIFIER);
            if (codeVerifier == null) {
                Throw.whenNotNull(pkceInfo,
                        () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'code_verifier'"));

                return;
            }

            Throw.whenNull(pkceInfo,
                    () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'code_challenge' from authorization"));

            String localCodeChallenge = pkceInfo.getMethod().calculateChallenge(codeVerifier);
            Throw.whenNot(localCodeChallenge.equals(pkceInfo.getChallenge()),
                    () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "code challenge validation failed"));
        }

        public TokenRequest parseRequest(AuthorizationAuthority verifier, ParamReader params) throws InvalidRequestException {
            AuthorizationCodePayload code = new AuthorizationCodePayload(params.extractSingletonParam(PARAM_CODE));
            UserAuthorization order = verifier.readAndVerifyAuthorizationCode(code);
            Throw.whenNull(order,
                    () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_GRANT, "invalid code"));

            checkClientId(params, order.getSpec().getClientId());
            checkScopes(params, order.getSpec().getScopes());
            checkRedirectUri(params, order.isRedirectUriProvided(), order.getRedirectUri());
            checkPkce(params, order.getPkceInfo());

            return new TokenRequest.AuthorizationCode(order);
        }
    }

    private static class GrantClientCredentialsParser {

        private GrantClientCredentialsParser() {
        }

        private static List<String> parseScopes(ParamReader params) throws InvalidRequestException {
            return Optional.ofNullable(params.maybeExtractSingletonParam(PARAM_SCOPE))
                    .map(str -> List.of(str.split(" ")))
                    .orElse(null);
        }

        public TokenRequest parseRequest(ParamReader params) throws InvalidRequestException {
            String clientId = params.extractSingletonParam(PARAM_CLIENT_ID);
            List<String> scopes = parseScopes(params);

            return new TokenRequest.ClientCredentials(clientId, scopes);
        }
    }

    private static class GrantRefreshTokenParser {

        private GrantRefreshTokenParser() {
        }

        public TokenRequest parseRequest(AuthorizationAuthority verifier, ParamReader params) throws InvalidRequestException {
            RefreshTokenPayload token = new RefreshTokenPayload(params.extractSingletonParam(PARAM_CODE));
            UserAuthorization order = verifier.readAndVerifyRefreshToken(token);
            Throw.whenNull(order,
                    () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_GRANT, "invalid code"));

            checkClientId(params, order);
            checkScopes(params, order);

            return new TokenRequest.RefreshToken(order);
        }
    }
}
