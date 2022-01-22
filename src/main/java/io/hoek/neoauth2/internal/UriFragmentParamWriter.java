package io.hoek.neoauth2.internal;

import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public final class UriFragmentParamWriter extends ParamWriter<URI> {

    private final URI uri;
    private final StringBuilder fragment;

    public UriFragmentParamWriter(URI uri) {
        this.uri = uri;
        this.fragment = new StringBuilder();
    }

    @Override
    public void set(String param, String value) {
        if (fragment.length() != 0) {
            fragment.append("&");
        }

        fragment.append(URLEncoder.encode(param, StandardCharsets.UTF_8))
                .append("=")
                .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
    }

    @Override
    public void set(String param, long value) {
        set(param, String.valueOf(value));
    }

    public URI build() {
        return UriBuilder.fromUri(uri).fragment(fragment.toString()).build();
    }
}
