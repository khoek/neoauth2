package io.hoek.neoauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.hoek.neoauth2.backend.RegistrationAuthority;
import io.hoek.neoauth2.extension.OAuth21SpecOptIn;
import io.hoek.neoauth2.extension.OAuth21SpecViolation;
import io.hoek.neoauth2.internal.InvalidRequestException;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.model.CodeChallengeMethod;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.model.PkceInfo;
import io.hoek.neoauth2.model.ResponseType;

import javax.validation.constraints.NotNull;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

// Nonstandard features we support: * `authorization.nonce` (by default)
//                                  * `authorization.response_type=token` (Implicit flow) (by opt-in)

public class AuthorizationRequestParser {
    public static final int PKCE_CODE_CHALLENGE_MIN_LENGTH = 43;
    public static final int PKCE_CODE_CHALLENGE_MAX_LENGTH = 128;

    private final ObjectMapper mapper = new ObjectMapper();
    private final List<Extension> extensions = new ArrayList<>();

    AuthorizationRequestParser() {
    }

    private URI selectCandidateRedirectUri(Collection<URI> allowedUris, String strRedirectUri) throws InvalidRequestException {
        URI redirectUri;
        try {
            redirectUri = strRedirectUri == null ? null : new URI(strRedirectUri);
        } catch (URISyntaxException e) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "malformed redirect URI");
        }

        if (redirectUri == null) {
            if (allowedUris.size() != 1) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing redirect URI and no default registered");
            }

            return allowedUris.iterator().next();
        }

        if (allowedUris.stream().anyMatch(uri -> Util.doUrisMatch(redirectUri, uri))) {
            return redirectUri;
        }

        throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "redirect URI not registered");
    }

    private URI lookupAndValidateRedirectUri(Collection<URI> allowedUris, String strRedirectUri) throws InvalidRequestException {
        URI redirectUri = selectCandidateRedirectUri(allowedUris, strRedirectUri);

        if (!redirectUri.isAbsolute()) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "redirect URI is not absolute");
        }

        if (redirectUri.getHost() == null) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "redirect URI is missing host");
        }

        if (!"https".equals(redirectUri.getScheme()) && !Util.isLoopbackHost(redirectUri.getHost())) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "redirect URI is not https");
        }

        if (redirectUri.getFragment() != null) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "redirect URI has a fragment");
        }

        return redirectUri;
    }

    public AuthorizationRequest parse(RegistrationAuthority registrationAuthority, UriInfo uriInfo) {
        return parse(registrationAuthority, uriInfo.getQueryParameters());
    }

    public AuthorizationRequest parse(RegistrationAuthority registrationAuthority, MultivaluedMap<String, String> params) {
        return parse(registrationAuthority, ParamReader.from(params::get));
    }

    public AuthorizationRequest parse(RegistrationAuthority registrationAuthority, ParamReader params) {
        final String state;
        try {
            state = params.maybeExtractSingletonParam("state");
        } catch (InvalidRequestException e) {
            throw e.toErrorPageException();
        }

        final String clientId;
        RegistrationAuthority.ClientInfo client;
        final URI redirectUri;
        final boolean redirectUriProvided;
        try {
            clientId = params.extractSingletonParam("client_id");
            client = registrationAuthority.lookupClientId(clientId);
            if (client == null) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_CLIENT, "client unknown");
            }

            String strRedirectUri = params.maybeExtractSingletonParam("redirect_uri");
            redirectUriProvided = strRedirectUri != null;
            redirectUri = lookupAndValidateRedirectUri(client.getAllowedRedirectUris(), strRedirectUri);
        } catch (InvalidRequestException e) {
            throw e.toErrorPageException(state);
        }

        try {
            return parseRequest(params, clientId, client, redirectUriProvided, redirectUri);
        } catch (InvalidRequestException e) {
            throw e.toRedirectException(redirectUri, state);
        }
    }

    private PkceInfo parsePkceInfo(ParamReader params, ResponseType responseType) throws InvalidRequestException {
        String strCodeChallengeMethod = params.maybeExtractSingletonParam("code_challenge_method");
        String codeChallenge = params.maybeExtractSingletonParam("code_challenge");

        if (codeChallenge != null && (codeChallenge.length() < PKCE_CODE_CHALLENGE_MIN_LENGTH || codeChallenge.length() > PKCE_CODE_CHALLENGE_MAX_LENGTH)) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "code challenge less than 43 or greater than 128 characters");
        }

        // SPEC NOTE: Optional, defaults to "plain". (Though accepting "plain" is also disabled by default.)
        CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.PLAIN;
        if (strCodeChallengeMethod != null) {
            try {
                codeChallengeMethod = Objects.requireNonNull(mapper.convertValue(strCodeChallengeMethod, CodeChallengeMethod.class));
            } catch (IllegalArgumentException e) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "unsupported code challenge method '" + strCodeChallengeMethod + "'");
            }
        }

        boolean anyPkceParamsPresent = (codeChallenge != null) || (strCodeChallengeMethod != null);
        OAuth21SpecViolation.DontRequirePkce dontRequirePkce =
                tryFindExtension(OAuth21SpecViolation.DontRequirePkce.class);

        // PKCE on by default for all but the 'implicit' flow, which is not part of OAuth 2.1 (and doesn't support it).
        if (!anyPkceParamsPresent) {
            if ((responseType == ResponseType.IMPLICIT) || (dontRequirePkce != null)) {
                return null;
            }
        }

        // PKCE doesn't make sense with the implicit flow.
        if (responseType == ResponseType.IMPLICIT) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "implicit flow doesn't support PKCE");
        }

        // Even if PKCE isn't required, a `code_challenge_method` without a `code_challenge` doesn't make sense.
        if (codeChallenge == null) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'code_challenge'");
        }

        OAuth21SpecOptIn.AllowPlainCodeChallengeMethod allowPlainCodeChallengeMethod =
                tryFindExtension(OAuth21SpecOptIn.AllowPlainCodeChallengeMethod.class);
        if ((codeChallengeMethod == CodeChallengeMethod.PLAIN) && allowPlainCodeChallengeMethod == null) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "challenge code method 'plain' disallowed");
        }

        return new PkceInfo(codeChallengeMethod, codeChallenge);
    }

    private @NotNull ResponseType parseResponseType(ParamReader params) throws InvalidRequestException {
        String strResponseType = params.maybeExtractSingletonParam("response_type");
        String nonce = params.maybeExtractSingletonParam("nonce");

        ResponseType responseType = null;
        if (strResponseType != null) {
            try {
                responseType = Objects.requireNonNull(mapper.convertValue(strResponseType, ResponseType.class));
            } catch (IllegalArgumentException e) {
                throw new InvalidRequestException(ErrorResponse.DESC_UNSUPPORTED_RESPONSE_TYPE, "unsupported response type '" + strResponseType + "'");
            }
        }

        if (responseType == null) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'response_type'");
        }

        OAuth21SpecViolation.AllowImplicit ruleAllowImplicit = tryFindExtension(OAuth21SpecViolation.AllowImplicit.class);
        if (responseType == ResponseType.IMPLICIT) {
            if (ruleAllowImplicit == null) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "response type 'token' disallowed");
            }

            if (nonce == null && ruleAllowImplicit.shouldRequireNonce()) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "parameter 'nonce' required for implicit grant");
            }
        }

        return responseType;
    }

    private @NotNull List<String> parseScopes(ParamReader params, RegistrationAuthority.ClientInfo client) throws InvalidRequestException {
        String strScope = params.maybeExtractSingletonParam("scope");
        List<String> scopes;
        if (strScope == null) {
            scopes = client.getDefaultScopes();
        } else {
            scopes = Arrays.asList(strScope.split(" "));
        }

        if (scopes == null) {
            // No scopes were explicitly provided and there are no registered defaults for this client.
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_SCOPE, "no 'scope' specified");
        }

        return scopes;
    }

    private AuthorizationRequest parseRequest(ParamReader params, String clientId, RegistrationAuthority.ClientInfo client, boolean redirectUriProvided, URI redirectUri) throws InvalidRequestException {
        ResponseType responseType = parseResponseType(params);
        PkceInfo pkceInfo = parsePkceInfo(params, responseType);
        List<String> scopes = parseScopes(params, client);

        String state = params.maybeExtractSingletonParam("state");
        String nonce = params.maybeExtractSingletonParam("nonce");

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
        if (!ext.getClass().getPackageName().equals(AuthorizationRequestParser.class.getPackageName() + ".extension")) {
            throw new IllegalArgumentException("Custom extensions are not supported! (" + ext.getClass() + ")");
        }
    }

    public AuthorizationRequestParser addExtension(Extension newExt) {
        // TODO: Replace with `sealed` once we can support Java 17.
        enforceExtensionsSealed(newExt);

        if (extensions.stream()
                .anyMatch(oldExt -> oldExt.getClass().equals(newExt.getClass()))) {
            throw new IllegalArgumentException("duplicate extension: " + newExt.getClass());
        }

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
