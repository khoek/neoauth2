package io.hoek.neoauth2.model;

import io.hoek.neoauth2.internal.ParamWriter;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class AuthorizationCodePayload implements ParamWriter.Writable {
    private final String code;

    @Override
    public void writeTo(ParamWriter writer) {
        writer.set("code", code);
    }
}
