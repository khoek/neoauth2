package io.hoek.neoauth2.model;

import io.hoek.neoauth2.internal.ParamWriter;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class RefreshTokenPayload implements ParamWriter.Writable {
    private final String refreshToken;

    @Override
    public void writeTo(ParamWriter<?> writer) {
        writer.set("refresh_token", refreshToken);
    }
}
