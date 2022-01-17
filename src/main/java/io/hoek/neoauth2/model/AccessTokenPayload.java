package io.hoek.neoauth2.model;

import io.hoek.neoauth2.ParamWriter;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public final class AccessTokenPayload implements ParamWriter.Writable {

    public static final String TOKEN_TYPE_BEARER = "Bearer";

    private final String accessToken;
    private final String tokenType;
    private final long expireInSeconds;
    private final List<String> scopes;

    @Override
    public void writeTo(ParamWriter writer) {
        writer.set("access_token", accessToken);
        writer.set("token_type", tokenType);
        writer.set("expires_in", expireInSeconds);
        writer.set("scope", String.join(" ", scopes));
    }
}
