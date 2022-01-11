package io.hoek.neoauth2.provider.builtin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.model.AuthorizationCodePayload;
import io.hoek.neoauth2.provider.AuthorizationCodeIssuer;
import io.hoek.neoauth2.provider.AuthorizationCodeOrder;

import java.time.Instant;

public class JwtAuthorizationCodeIssuer implements AuthorizationCodeIssuer {
    private final ObjectMapper mapper = new ObjectMapper();
    private final DataStore dataStore;

    public JwtAuthorizationCodeIssuer(DataStore dataStore) {
        this.dataStore = dataStore;
    }

    private static AuthorizationCodeOrder verifyAndUnpackJwt(String jwt) {
        // FIXME first check whether the code is valid, not expired.

        throw new UnsupportedOperationException();
    }

    @Override
    public AuthorizationCodePayload issueAuthorizationCode(AuthorizationCodeOrder content, Instant expiry) {
        //        Jwt.issuer(selfIssuerUri)
        //                .subject(content.getUserId())
        //                .audience(selfIssuerUri)
        //                .expiresIn(Duration.ofSeconds(EXPIRES_IN_SECS))
        //                .issuedAt(Instant.now())
        //                .claim("client_id", content.getClientId())
        //                .claim("scope", String.join(" ", content.getScopes()))
        //                // FIXME Don't do this, just put all this junk in a single json guy
        //                .claim("x-hoek-neoauth-redirect_uri", content.getRedirectUri())
        //                .claim("x-hoek-neoauth-redirect_uri_provided", content.wasRedirectUriProvided())
        //                // FIXME Doesn't the spec say something about not being able to read the code challenge?
        //                .claim("x-hoek-neoauth-code_challenge", content.getCodeChallenge())
        //                .claim("x-hoek-neoauth-code_challenge", content.getCodeChallenge())
        //                .jwe()
        //                .;
        //
        //        //                .groups(identity.getRoles())
        //
        //        return new AuthorizationCodePayload(code);

        // FIXME implement
        throw new UnsupportedOperationException();
    }

    private boolean checkCodeReuseIsPlausiblyDeniable(AuthorizationCodePayload payload) {
        if (dataStore == null) {
            return false;
        }

        String key = Util.calculateSha256Base64UrlEncodedWithoutPadding(payload.getCode());
        DataStore.Entry entry = dataStore.get(key);
        if (entry == null) {
            // We should have already checked that this is a valid unexpired code, so this shouldn't have happened.
            throw new IllegalStateException("datastore dropped code  [" + key + "]: " + payload.getCode());
        }

        // TODO: Ideally we should revoke the token issued with the first use of the supplied code, since the spec
        //       says we should assume a compromise in this situation. Perhaps add a facility to report such
        //       violations.
        return entry.getAccessCount().isFirst();
    }

    @Override
    public AuthorizationCodeOrder readAndVerifyAuthorizationCode(AuthorizationCodePayload payload) {
        AuthorizationCodeOrder order = verifyAndUnpackJwt(payload.getCode());
        if (order == null) {
            return null;
        }

        if (!checkCodeReuseIsPlausiblyDeniable(payload)) {
            return null;
        }

        return order;
    }
}
