package io.hoek.neoauth2.internal;

import io.hoek.neoauth2.ParamReader;
import io.hoek.neoauth2.model.ErrorResponse;
import lombok.SneakyThrows;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.net.Inet4Address;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

public class Util {

    private Util() {
    }

    // We are intentionally too strict.
    public static boolean isLoopbackHost(String host) {
        host = host.toLowerCase();
        return host.equals("localhost") || host.equals("127.0.0.1") || host.equals("::1");
    }

    // SPEC NOTE: The spec allows loopback redirects to match where there is only a difference of port (compared to
    // that which was registered).
    public static boolean doUrisMatch(URI a, URI b) {
        if (a.equals(b)) {
            return true;
        }

        if (a.getHost() == null || b.getHost() == null) {
            return false;
        }

        return isLoopbackHost(a.getHost())
                && isLoopbackHost(b.getHost())
                && UriBuilder.fromUri(a)
                .host(b.getHost())
                .port(b.getPort())
                .build().equals(b);
    }

    public static String generateRandomBytesBase64UrlEncodedWithoutPadding(SecureRandom random, int numBytes) {
        byte[] raw = new byte[numBytes];
        random.nextBytes(raw);
        return calculateSha256Base64UrlEncodedWithoutPadding(raw);
    }

    public static String calculateSha256Base64UrlEncodedWithoutPadding(String raw) {
        return calculateSha256Base64UrlEncodedWithoutPadding(raw.getBytes(StandardCharsets.UTF_8));
    }

    @SneakyThrows
    public static String calculateSha256Base64UrlEncodedWithoutPadding(byte[] bytes) {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    public static Response.ResponseBuilder addSecurityCacheControlHeaders(Response.ResponseBuilder builder) {
        return builder.header("Cache-Control", "no-store");
    }
}
