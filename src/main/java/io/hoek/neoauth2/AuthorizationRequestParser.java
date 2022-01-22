package io.hoek.neoauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.hoek.neoauth2.backend.ClientRegistration;
import io.hoek.neoauth2.extension.OAuth21SpecOption;
import io.hoek.neoauth2.extension.OAuth21SpecViolation;
import io.hoek.neoauth2.internal.InvalidRequestException;
import io.hoek.neoauth2.internal.UriQueryParamWriter;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.model.CodeChallengeMethod;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.model.PkceInfo;
import io.hoek.neoauth2.model.ResponseType;
import io.hoek.util.function.Throw;

import javax.validation.constraints.NotNull;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

// Nonstandard features we support: * `authorization.nonce` (by default)
//                                  * `authorization.response_type=token` (Implicit flow) (by opt-in)

public class AuthorizationRequestParser {

    public static final int PKCE_CODE_CHALLENGE_MIN_LENGTH = 43;
    public static final int PKCE_CODE_CHALLENGE_MAX_LENGTH = 128;

    public static final String PARAM_CLIENT_ID = "client_id";
    public static final String PARAM_RESPONSE_TYPE = "response_type";
    public static final String PARAM_REDIRECT_URI = "redirect_uri";
    public static final String PARAM_CODE_CHALLENGE_METHOD = "code_challenge_method";
    public static final String PARAM_CODE_CHALLENGE = "code_challenge";
    public static final String PARAM_SCOPE = "scope";
    public static final String PARAM_STATE = "state";
    public static final String PARAM_NONCE = "nonce";

    private final ObjectMapper mapper = new ObjectMapper();
    private final List<Extension> extensions = new ArrayList<>();

    AuthorizationRequestParser() {
    }

    private URI selectCandidateRedirectUri(Collection<URI> allowedUris, String strRedirectUri) throws InvalidRequestException {
        URI redirectUri = Throw.insteadOf(URISyntaxException.class,
                () -> strRedirectUri == null ? null : new URI(strRedirectUri),
                () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "malformed redirect URI"));

        if (redirectUri == null) {
            Throw.whenNot(allowedUris.size() == 1,
                    () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing redirect URI and no default registered"));

            return allowedUris.iterator().next();
        }

        if (allowedUris.stream().anyMatch(uri -> Util.doUrisMatch(redirectUri, uri))) {
            return redirectUri;
        }

        throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "redirect URI not registered");
    }

    private URI lookupAndValidateRedirectUri(Collection<URI> allowedUris, String strRedirectUri) throws InvalidRequestException {
        URI redirectUri = selectCandidateRedirectUri(allowedUris, strRedirectUri);

        Throw.whenNot(redirectUri.isAbsolute(),
                () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "redirect URI is not absolute"));

        Throw.whenNull(redirectUri.getHost(),
                () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "redirect URI is missing host"));

        Throw.whenNot("https".equals(redirectUri.getScheme()) || Util.isLoopbackHost(redirectUri.getHost()),
                () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "redirect URI is not https"));

        Throw.whenNotNull(redirectUri.getFragment(),
                () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "redirect URI has a fragment"));

        return redirectUri;
    }

    public AuthorizationRequestGranter parse(ClientRegistration client, UriInfo uriInfo) {
        return parse(client, uriInfo.getQueryParameters());
    }

    public AuthorizationRequestGranter parse(ClientRegistration client, MultivaluedMap<String, String> params) {
        return parse(client, ParamReader.from(params::get));
    }

    public AuthorizationRequestGranter parse(ClientRegistration client, ParamReader params) {
        Objects.requireNonNull(client);
        Objects.requireNonNull(params);

        // TODO: Add configurable error pages if we fail early here, before we can safely issue an error redirect.

        // The only way this can throw is if `state` appears as a parameter multiple times (it is fine if `state` is not
        // present), and we don't bother to keep track of this and issue an error redirect if the redirect URL can be
        // validated next: just give up now and show an error page.
        String state = Throw.insteadOf(InvalidRequestException.class,
                () -> params.maybeExtractSingletonParam(PARAM_STATE),
                e -> new OAuthReponse.JsonPage(Response.Status.BAD_REQUEST, e.getErrorResponse()));

        // Next parse and validate the redirect URI: we again have to show an error page if this step fails.
        URI redirectUri = Throw.insteadOf(InvalidRequestException.class,
                () -> lookupAndValidateRedirectUri(client.getAllowedRedirectUris(), params.maybeExtractSingletonParam(PARAM_REDIRECT_URI)),
                e -> new OAuthReponse.JsonPage(Response.Status.BAD_REQUEST, e.getErrorResponseWithState(state)));

        // Finally, parse the actual request and return any errors via a query parameter redirect.
        AuthorizationRequest request = Throw.insteadOf(InvalidRequestException.class,
                () -> parseRequest(params, parseResponseType(params), client, redirectUri),
                e -> new OAuthReponse.Redirect(new UriQueryParamWriter(redirectUri), e.getErrorResponseWithState(state))
        );

        return new AuthorizationRequestGranter(client, request);
    }

    private PkceInfo parsePkceInfo(ParamReader params, ResponseType responseType) throws InvalidRequestException {
        String strCodeChallengeMethod = params.maybeExtractSingletonParam(PARAM_CODE_CHALLENGE_METHOD);
        String codeChallenge = params.maybeExtractSingletonParam(PARAM_CODE_CHALLENGE);

        Throw.when(codeChallenge != null && (codeChallenge.length() < PKCE_CODE_CHALLENGE_MIN_LENGTH || codeChallenge.length() > PKCE_CODE_CHALLENGE_MAX_LENGTH),
                () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "code challenge less than 43 or greater than 128 characters"));

        // SPEC NOTE: Optional, defaults to "plain". (Though accepting "plain" is also disabled by default.)
        CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.PLAIN;
        if (strCodeChallengeMethod != null) {
            codeChallengeMethod = Throw.insteadOf(IllegalArgumentException.class,
                    () -> Objects.requireNonNull(mapper.convertValue(strCodeChallengeMethod, CodeChallengeMethod.class)),
                    () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "unsupported code challenge method '" + strCodeChallengeMethod + "'"));
        }

        OAuth21SpecViolation.DontRequirePkce dontRequirePkce =
                tryFindExtension(OAuth21SpecViolation.DontRequirePkce.class);
        boolean forceUsingPkce = (responseType != ResponseType.IMPLICIT) && (dontRequirePkce == null);
        boolean anyPkceParamsPresent = (strCodeChallengeMethod != null) || (codeChallenge != null);

        // PKCE on by default for all but the 'implicit' flow, which is not part of OAuth 2.1 (and doesn't support it).
        if (!forceUsingPkce && !anyPkceParamsPresent) {
            return null;
        }

        // PKCE doesn't make sense with the implicit flow.
        Throw.when(responseType == ResponseType.IMPLICIT,
                () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "implicit flow doesn't support PKCE"));

        // Even if PKCE isn't required, a `code_challenge_method` without a `code_challenge` doesn't make sense.
        Throw.when(codeChallenge == null,
                () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'code_challenge'"));

        OAuth21SpecOption.AllowPlainCodeChallengeMethod allowPlainCodeChallengeMethod =
                tryFindExtension(OAuth21SpecOption.AllowPlainCodeChallengeMethod.class);
        Throw.when((codeChallengeMethod == CodeChallengeMethod.PLAIN) && allowPlainCodeChallengeMethod == null,
                () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "challenge code method 'plain' disallowed"));

        return new PkceInfo(codeChallengeMethod, codeChallenge);
    }

    private @NotNull ResponseType parseResponseType(ParamReader params) throws InvalidRequestException {
        String strResponseType = params.extractSingletonParam(PARAM_RESPONSE_TYPE);

        return Throw.insteadOf(IllegalArgumentException.class,
                () -> Objects.requireNonNull(mapper.convertValue(strResponseType, ResponseType.class)),
                () -> new InvalidRequestException(ErrorResponse.DESC_UNSUPPORTED_RESPONSE_TYPE, "unsupported response type '" + strResponseType + "'"));
    }

    private void checkResponseType(ResponseType responseType, String nonce) throws InvalidRequestException {
        OAuth21SpecViolation.AllowImplicit ruleAllowImplicit = tryFindExtension(OAuth21SpecViolation.AllowImplicit.class);
        if (responseType == ResponseType.IMPLICIT) {
            Throw.whenNull(ruleAllowImplicit,
                    () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "response type 'token' disallowed"));

            Throw.when(nonce == null && ruleAllowImplicit.shouldRequireNonce(),
                    () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "parameter 'nonce' required for implicit grant"));
        }
    }

    private @NotNull List<String> parseScopes(ParamReader params, ClientRegistration client) throws InvalidRequestException {
        List<String> scopes = Optional.ofNullable(params.maybeExtractSingletonParam(PARAM_SCOPE))
                .map(str -> List.of(str.split(" ")))
                .orElseGet(client::getDefaultScopes);

        return Throw.whenNull(scopes,
                () -> new InvalidRequestException(ErrorResponse.DESC_INVALID_SCOPE, "no 'scope' specified"));
    }

    private AuthorizationRequest parseRequest(ParamReader params, ResponseType responseType, ClientRegistration client, URI redirectUri) throws InvalidRequestException {
        PkceInfo pkceInfo = parsePkceInfo(params, responseType);
        List<String> scopes = parseScopes(params, client);

        // TODO: Allow the `client_id` to be missing if the client has been authenticated by alternative means.
        String clientId = params.extractSingletonParam(PARAM_CLIENT_ID);
        boolean redirectUriProvided = params.maybeExtractSingletonParam(PARAM_REDIRECT_URI) != null;
        String state = params.maybeExtractSingletonParam(PARAM_STATE);
        String nonce = params.maybeExtractSingletonParam(PARAM_NONCE);

        checkResponseType(responseType, nonce);

        switch (responseType) {
            case IMPLICIT:
                return new AuthorizationRequest.Implicit(clientId, redirectUriProvided, redirectUri, scopes, state, nonce);
            case AUTHORIZATION_CODE:
                return new AuthorizationRequest.AuthorizationCode(clientId, redirectUriProvided, redirectUri, scopes, state, nonce, pkceInfo);
            default:
                throw new UnsupportedOperationException();
        }
    }

    private void enforceExtensionsSealed(Extension ext) {
        Throw.whenNot(ext.getClass().getPackageName()
                        .equals(AuthorizationRequestParser.class.getPackageName() + ".extension"),
                () -> new IllegalArgumentException("Custom extensions are not supported! (" + ext.getClass() + ")"));
    }

    public AuthorizationRequestParser addExtension(Extension newExt) {
        // TODO: Replace with `sealed` once we can support Java 17.
        enforceExtensionsSealed(newExt);

        Throw.when(extensions.stream().anyMatch(
                        oldExt -> oldExt.getClass().equals(newExt.getClass())),
                () -> new IllegalArgumentException("duplicate extension: " + newExt.getClass()));

        this.extensions.add(newExt);
        return this;
    }

    public AuthorizationRequestParser addExtensions(Collection<Extension> extensions) {
        extensions.forEach(this::addExtension);
        return this;
    }

    private <T extends Extension> T tryFindExtension(Class<T> clazz) {
        // Note that we check and prohibit duplicates in `AuthorizationRequestParser.withExtension()`.
        return extensions.stream()
                .filter(ext -> ext.getClass().equals(clazz))
                .map(clazz::cast)
                .findFirst()
                .orElse(null);
    }

    public static abstract class Extension {

    }
}
