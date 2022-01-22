package io.hoek.neoauth2.internal;

import javax.ws.rs.core.UriBuilder;
import java.net.URI;

public final class UriQueryParamWriter extends ParamWriter<URI> {

    private final UriBuilder builder;

    public UriQueryParamWriter(URI uri) {
        this.builder = UriBuilder.fromUri(uri);
    }

    @Override
    public void set(String param, String value) {
        builder.replaceQueryParam(param, value);
    }

    @Override
    public void set(String param, long value) {
        builder.replaceQueryParam(param, value);
    }

    public URI build() {
        return builder.build();
    }
}
