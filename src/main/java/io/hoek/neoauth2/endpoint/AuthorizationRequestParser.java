package io.hoek.neoauth2.endpoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.hoek.neoauth2.endpoint.ext.OAuth21SpecOptIn;
import io.hoek.neoauth2.endpoint.ext.OAuth21SpecViolation;
import io.hoek.neoauth2.internal.InvalidRequestException;
import io.hoek.neoauth2.internal.ParamReader;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.model.CodeChallengeMethod;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.model.ResponseType;
import io.hoek.neoauth2.provider.RegistrationAuthority;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

// Nonstandard features we support: * `authorization.nonce` (by default)
//                                  * `authorization.response_type=token` (Implicit flow) (by opt-in)

public class AuthorizationRequestParser {
    private final ObjectMapper mapper = new ObjectMapper();
    private final List<Extension> extensions = new ArrayList<>();

    AuthorizationRequestParser() {
    }

    private URI lookupRedirectUri(RegistrationAuthority.ClientInfo client, String strRedirectUri) throws InvalidRequestException {
        URI redirectUri;
        try {
            redirectUri = strRedirectUri == null ? null : new URI(strRedirectUri);
        } catch (URISyntaxException e) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "malformed redirect URI");
        }

        Collection<URI> uris = client.getAllowedRedirectUris();

        if (redirectUri == null) {
            if (uris.size() != 1) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "no default redirect URI");
            }

            return uris.iterator().next();
        }

        if (uris.stream().anyMatch(uri -> Util.doUrisMatch(redirectUri, uri))) {
            return redirectUri;
        }

        throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "invalid redirect URI");
    }

    private URI validateRedirectUri(URI redirectUri) throws InvalidRequestException {
        // FIXME learn about the dangers of an open redirect, e.g. we'd want to make sure we are not being redirected
        // to any sub-URI of api.hoek.io...
        //
        // FIXME VERIFYING THIS, I GUESS IF PRESENT, IS A SECURITY THING
        // THERE ARE MANY POSSIBILITIES, E.G. WE HAVE TO APPEND WHILE SUPPORTING EXISTING QUERY PARAMS,
        // BUT NOT ALLOW A FRAGMENTS,
        // ALSO WE NEED TO CHECK THE DOMAIN IT HINK???
        // ALSO HTTPS
        //
        //        Authorization servers MUST require clients to register their complete
        //        redirect URI (including the path component) and reject authorization
        //        requests that specify a redirect URI that doesn't exactly match one
        //        that was registered; the exception is loopback redirects, where an
        //        exact match is required except for the port URI component.
        //

        if (!"https".equals(redirectUri.getScheme()) && !Util.isLoopbackHost(redirectUri.getHost())) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "redirect URI is not https");
        }

        if (redirectUri.getFragment() != null) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "redirect URI has a fragment");
        }

        return redirectUri;
    }

    public AuthorizationRequest parse(RegistrationAuthority registrationAuthority, UriInfo uriInfo) throws ReturnErrorResponseException {
        return parse(registrationAuthority, uriInfo.getQueryParameters());
    }

    public AuthorizationRequest parse(RegistrationAuthority registrationAuthority, MultivaluedMap<String, String> params) throws ReturnErrorResponseException {
        return parse(registrationAuthority, params::get);
    }

    public AuthorizationRequest parse(RegistrationAuthority registrationAuthority, ParamReader params) throws ReturnErrorResponseException {
        final String state;
        try {
            state = Util.maybeExtractSingletonParam(params, "state");
        } catch (InvalidRequestException e) {
            throw e.toErrorPageException();
        }

        final String clientId;
        RegistrationAuthority.ClientInfo client;
        final URI redirectUri;
        final boolean redirectUriProvided;
        try {
            clientId = Util.extractSingletonParam(params, "client_id");
            client = registrationAuthority.lookupClientId(clientId);
            if (client == null) {
                throw new InvalidRequestException(ErrorResponse.DESC_UNAUTHORIZED_CLIENT, "client unknown");
            }

            String strRedirectUri = Util.maybeExtractSingletonParam(params, "redirect_uri");
            redirectUriProvided = strRedirectUri != null;
            redirectUri = lookupRedirectUri(client, strRedirectUri);
            validateRedirectUri(redirectUri);
        } catch (InvalidRequestException e) {
            throw e.toErrorPageException(state);
        }

        try {
            return parseRequest(params, clientId, client, redirectUriProvided, redirectUri, state);
        } catch (InvalidRequestException e) {
            throw e.toRedirectException(redirectUri, state);
        }
    }

    public AuthorizationRequest parseRequest(ParamReader params, String clientId, RegistrationAuthority.ClientInfo client, boolean redirectUriProvided, URI redirectUri, String state) throws InvalidRequestException {
        String strScope = Util.maybeExtractSingletonParam(params, "scope");
        List<String> scopes;
        if (strScope == null) {
            scopes = client.getDefaultScopes();
        } else {
            scopes = Arrays.asList(strScope.split(" "));
        }

        if (scopes == null) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_SCOPE, "no 'scope' specified");
        }

        String nonce = Util.maybeExtractSingletonParam(params, "nonce");
        String strResponseType = Util.maybeExtractSingletonParam(params, "response_type");

        ResponseType responseType = ResponseType.AUTHORIZATION_CODE;
        if (strResponseType != null) {
            try {
                responseType = mapper.convertValue(strResponseType, ResponseType.class);
            } catch (IllegalArgumentException e) {
                throw new InvalidRequestException(ErrorResponse.DESC_UNSUPPORTED_RESPONSE_TYPE, "unsupported response type '" + strResponseType + "'");
            }
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

        String strCodeChallengeMethod = Util.maybeExtractSingletonParam(params, "code_challenge_method");
        String codeChallenge = Util.maybeExtractSingletonParam(params, "code_challenge");

        // SPEC NOTE: Optional, defaults to "plain". (Though accepting "plain" is also disabled by default.)
        CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.PLAIN;
        if (strCodeChallengeMethod != null) {
            try {
                codeChallengeMethod = mapper.convertValue(strCodeChallengeMethod, CodeChallengeMethod.class);
            } catch (IllegalArgumentException e) {
                throw new InvalidRequestException(ErrorResponse.DESC_UNSUPPORTED_RESPONSE_TYPE, "unsupported code challenge method '" + strCodeChallengeMethod + "'");
            }
        }

        boolean anyPkceParamsPresent = (codeChallenge != null) || (strCodeChallengeMethod != null);

        // PKCE doesn't make sense with the implicit flow.
        if(responseType == ResponseType.IMPLICIT && anyPkceParamsPresent) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "implicit flow doesn't support PKCE");
        }

        OAuth21SpecViolation.DontRequirePkce dontRequirePkce = tryFindExtension(OAuth21SpecViolation.DontRequirePkce.class);
        OAuth21SpecOptIn.AllowPlainCodeChallengeMethod allowPlainCodeChallengeMethod = tryFindExtension(OAuth21SpecOptIn.AllowPlainCodeChallengeMethod.class);

        // PKCE on by default for all but the 'implicit' flow, which is not part of OAuth 2.1 (and doesn't support it).
        boolean usingPkce = anyPkceParamsPresent || ((responseType != ResponseType.IMPLICIT) && dontRequirePkce == null);

        if (usingPkce) {
            // Even if PKCE isn't required, a `code_challenge_method` without a `code_challenge` doesn't make sense.
            if (codeChallenge == null) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing 'code_challenge'");
            }

            if (codeChallengeMethod == CodeChallengeMethod.PLAIN && allowPlainCodeChallengeMethod == null) {
                throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "challenge code method 'plain' disallowed");
            }
        } else {
            codeChallengeMethod = null;
        }

        switch (responseType) {
            case IMPLICIT: {
                return new AuthorizationRequest.Implicit(clientId, redirectUriProvided, redirectUri, scopes, state, nonce);
            }
            case AUTHORIZATION_CODE: {
                return new AuthorizationRequest.AuthorizationCode(clientId, redirectUriProvided, redirectUri, scopes, state, nonce, codeChallengeMethod, codeChallenge);
            }
        }

        throw new UnsupportedOperationException();
    }

    private void enforceExtensionsSealed(Extension ext) {
        if (!ext.getClass().getPackageName().equals(AuthorizationRequestParser.class.getPackageName() + ".ext")) {
            throw new IllegalArgumentException("Custom extensions are not supported! (" + ext.getClass() + ")");
        }
    }

    public AuthorizationRequestParser addExtension(Extension newExt) {
        // TODO Replace with `sealed` once we can support Java 17.
        enforceExtensionsSealed(newExt);

        if (extensions.stream()
                .anyMatch(oldExt -> oldExt.getClass().equals(newExt.getClass()))) {
            throw new IllegalArgumentException("duplicate rule: " + newExt.getClass());
        }

        this.extensions.add(newExt);
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
