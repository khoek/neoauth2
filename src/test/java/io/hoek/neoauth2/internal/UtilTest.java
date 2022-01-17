package io.hoek.neoauth2.internal;

import io.hoek.neoauth2.ParamReader;
import org.junit.jupiter.api.Test;

import javax.ws.rs.core.Response;
import java.net.URI;
import java.security.SecureRandom;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class UtilTest {

    @Test
    public void testMaybeExtract() throws InvalidRequestException {
        assertNull(
                ParamReader.from(param -> null).maybeExtractSingletonParam("x"));
        assertNull(
                ParamReader.from(param -> List.of()).maybeExtractSingletonParam("y"));

        assertEquals("bbb",
                ParamReader.from(param -> param.equals("aaa") ? List.of("bbb") : List.of()).maybeExtractSingletonParam("aaa"));
        assertNull(
                ParamReader.from(param -> param.equals("aaa") ? List.of("bbb") : List.of()).maybeExtractSingletonParam("ccc"));

        assertThrows(InvalidRequestException.class, () ->
                ParamReader.from(param -> List.of("bbb", "bbb")).maybeExtractSingletonParam("aaa"));
        assertThrows(InvalidRequestException.class, () ->
                ParamReader.from(param -> List.of("bbb", "ccc")).maybeExtractSingletonParam("aaa"));
    }

    @Test
    public void testExtract() throws InvalidRequestException {
        assertThrows(InvalidRequestException.class, () ->
                ParamReader.from(param -> null).extractSingletonParam("x"));
        assertThrows(InvalidRequestException.class, () ->
                ParamReader.from(param -> List.of()).extractSingletonParam("y"));

        assertEquals("bbb",
                ParamReader.from(param -> param.equals("aaa") ? List.of("bbb") : List.of()).extractSingletonParam("aaa"));
        assertThrows(InvalidRequestException.class, () ->
                ParamReader.from(param -> param.equals("aaa") ? List.of("bbb") : List.of()).extractSingletonParam("ccc"));

        assertThrows(InvalidRequestException.class, () ->
                ParamReader.from(param -> List.of("bbb", "bbb")).extractSingletonParam("aaa"));
        assertThrows(InvalidRequestException.class, () ->
                ParamReader.from(param -> List.of("bbb", "ccc")).extractSingletonParam("aaa"));
    }

    @Test
    public void testIsLoopback() {
        assertTrue(Util.isLoopbackHost("localhost"));
        assertTrue(Util.isLoopbackHost("LOCALHOST"));
        assertTrue(Util.isLoopbackHost("LoCaLhOsT"));
        assertTrue(Util.isLoopbackHost("127.0.0.1"));
        assertTrue(Util.isLoopbackHost("::1"));

        assertFalse(Util.isLoopbackHost("localhosta"));
        assertFalse(Util.isLoopbackHost("192.168.1.1"));
        // We are intentionally too strict.
        assertFalse(Util.isLoopbackHost("127.0.0.2"));
    }

    private void assertSymmetricMatch(boolean yes, String a, String b) {
        assertEquals(yes, Util.doUrisMatch(URI.create(a), URI.create(b)));
        assertEquals(yes, Util.doUrisMatch(URI.create(b), URI.create(a)));
    }

    @Test
    public void testUrisMatch() {
        assertSymmetricMatch(true, "no/host", "no/host");
        assertSymmetricMatch(false, "no/host", "no/host/another");
        assertSymmetricMatch(false, "https://no/host", "no/host");

        assertSymmetricMatch(true, "https://hoek.io:8080", "https://hoek.io:8080");
        assertSymmetricMatch(false, "https://hoek.io:8080", "https://hoek.io:8080/test2");
        assertSymmetricMatch(false, "https://hoek.io:8080", "https://hoek.io:9090");

        assertSymmetricMatch(true, "https://localhost", "https://localhost:8080");
        assertSymmetricMatch(true, "https://localhost:8080", "https://localhost:8080");
        assertSymmetricMatch(true, "https://LOCALHOST:8080", "https://localhost:9090");

        assertSymmetricMatch(true, "https://127.0.0.1:8080", "https://localhost:9090");
        assertSymmetricMatch(false, "https://localhost:8080/test1", "https://localhost:8080");
        assertSymmetricMatch(false, "https://localhost:8080", "https://hoek.io:8080");
        assertSymmetricMatch(false, "https://hoek.io:8080", "https://localhost:8080");
    }

    @Test
    public void testSha256UrlEncoded() {
        assertEquals("x8PejGypC0FSjCkt4diQxSuuL6cTDSYBqeWT71OwXzk",
                Util.calculateSha256Base64UrlEncodedWithoutPadding("sdfasdfasdfasdfasdfasdddddssfasd"));

        assertEquals("x8PejGypC0FSjCkt4diQxSuuL6cTDSYBqeWT71OwXzk",
                Util.generateRandomBytesBase64UrlEncodedWithoutPadding(new SecureRandom() {
                    @Override
                    public void nextBytes(byte[] bytes) {
                        System.arraycopy(new byte[]{
                                0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66, 0x61, 0x73,
                                0x64, 0x66, 0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64,
                                0x66, 0x61, 0x73, 0x64, 0x64, 0x64, 0x64, 0x64, 0x73,
                                0x73, 0x66, 0x61, 0x73, 0x64
                        }, 0, bytes, 0, 32);
                    }
                }, 32));
    }

    @Test
    public void testCacheControl() {
        assertEquals("no-store", Util.addSecurityCacheControlHeaders(Response.ok()).build()
                .getHeaderString("Cache-Control"));
    }
}
