package io.hoek.neoauth2.provider.builtin;

import io.hoek.neoauth2.model.AccessTokenPayload;
import io.hoek.neoauth2.provider.AccessTokenIssuer;
import io.hoek.neoauth2.provider.AccessTokenOrder;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;

import java.security.PrivateKey;
import java.util.Collection;

public class Rfc9068AccessTokenIssuer implements AccessTokenIssuer {
    private final String selfIssuerUri;
    private final Collection<String> supportedScopes;
    private final String keyId;
    private final PrivateKey privateKey;

    public Rfc9068AccessTokenIssuer(String selfIssuerUri, Collection<String> supportedScopes, String keyId, PrivateKey privateKey) {
        this.selfIssuerUri = selfIssuerUri;
        this.supportedScopes = supportedScopes;
        this.keyId = keyId;
        this.privateKey = privateKey;
    }

    @Override
    public AccessTokenPayload issueAccessToken(AccessTokenOrder order) {
        JwtClaims claims = new JwtClaims();

        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(1);
        claims.setExpirationTimeMinutesInTheFuture(order.getExpiresInSeconds() * 60.f);

        claims.setIssuer(selfIssuerUri);
        claims.setAudience(order.getAud());
        claims.setSubject(order.getSub());
        claims.setClaim("client_id", order.getClientId());
        // FIXME optional
        claims.setClaim("scope", String.join(" ", order.getScopes()));
        if (order.getNonce() != null) {
            claims.setClaim("nonce", order.getNonce());
        }

        JsonWebSignature jws = new JsonWebSignature();
        jws.setHeader(HeaderParameterNames.TYPE, "at+JWT");
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue(keyId);

        jws.setKey(privateKey);
        jws.setPayload(claims.toJson());

        String accessToken;
        try {
            accessToken = jws.getCompactSerialization();
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }

        // FIXME when do we check the scopes? Gotta do it here or something and not just authorizations because
        // of the implicit method.

        return new AccessTokenPayload(accessToken, AccessTokenPayload.TOKEN_TYPE_BEARER, order.getExpiresInSeconds(), order.getScopes());
    }
}
