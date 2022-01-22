package io.hoek.neoauth2.backend.builtin;

import io.hoek.util.function.Catch;
import io.hoek.neoauth2.backend.AccessTokenIssuer;
import io.hoek.neoauth2.backend.AccessTokenOrder;
import io.hoek.neoauth2.model.AccessTokenPayload;
import io.hoek.util.function.Throw;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;

import java.security.PrivateKey;
import java.util.Map;

public class Rfc9068JwtAccessTokenIssuer implements AccessTokenIssuer {

    public static final String JWT_TYPE = "at+JWT";
    public static final String CLAIM_CLIENT_ID = "client_id";
    public static final String CLAIM_SCOPE = "scope";

    private final String selfIssuerUri;
    private final String privateKeyId;
    private final PrivateKey privateKey;

    public Rfc9068JwtAccessTokenIssuer(String selfIssuerUri, String privateKeyId, PrivateKey privateKey) {
        this.selfIssuerUri = selfIssuerUri;
        this.privateKeyId = privateKeyId;
        this.privateKey = privateKey;
    }

    @Override
    public AccessTokenPayload issueAccessToken(AccessTokenOrder order) {
        JwtClaims claims = new JwtClaims();

        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(1);
        claims.setExpirationTimeMinutesInTheFuture(((float) order.getExpiresInSecs()) / 60.f);

        claims.setIssuer(selfIssuerUri);
        claims.setClaim(CLAIM_CLIENT_ID, order.getSpec().getClientId());
        claims.setClaim(CLAIM_SCOPE, String.join(" ", order.getSpec().getScopes()));
        for (Map.Entry<String, String> claim : order.getSpec().getClaims().entrySet()) {
            claims.setClaim(claim.getKey(), claim.getValue());
        }

        JsonWebSignature jws = new JsonWebSignature();
        jws.setHeader(HeaderParameterNames.TYPE, JWT_TYPE);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue(privateKeyId);

        jws.setKey(privateKey);
        jws.setPayload(claims.toJson());

        String accessToken = Throw.asRuntime(jws::getCompactSerialization);

        return new AccessTokenPayload(
                accessToken,
                AccessTokenPayload.TOKEN_TYPE_BEARER,
                order.getExpiresInSecs(),
                order.getSpec()
                        .getScopes());
    }
}
