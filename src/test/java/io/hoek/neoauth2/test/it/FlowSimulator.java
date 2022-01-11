package io.hoek.neoauth2.test.it;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpResponseException;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.common.io.CharStreams;
import io.hoek.neoauth2.model.ErrorResponse;

import java.awt.*;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

public class FlowSimulator {
    private FlowSimulator() {
    }

    public interface Profile extends MockOAuth2Server.Configuration {
        URI buildEndpointParamsForAuthorization(URI authorizationUri);

        String buildEndpointParamsForToken(String code);
    }

    public static ObjectNode assertFlowSucceeds(Function<URI, Profile> profileBuilder) throws IOException {
        RedirectionCaptureServer redirect = new RedirectionCaptureServer(false, "code");

        Profile profile = profileBuilder.apply(redirect.getRedirectUri());
        MockOAuth2Server server = new MockOAuth2Server(profile);
        server.start();

        redirect.start();
        Desktop.getDesktop()
                .browse(profile.buildEndpointParamsForAuthorization(server.getAuthorizationUri()));
        redirect.waitForRequestAndStop();
        assertTrue(redirect.wasCaptureAsExpected());

        String code = redirect.getResponseParam("code");
        assertNotNull(code);
        assertNull(redirect.getResponseParam("error"), redirect.getResponseParam("error_message"));

        HttpResponse response = new NetHttpTransport().createRequestFactory().buildPostRequest(
                        new GenericUrl(server.getTokenUri()),
                        ByteArrayContent.fromString("application/x-www-form-urlencoded",
                                profile.buildEndpointParamsForToken(code)))
                .execute();
        String body = CharStreams.toString(new InputStreamReader(response.getContent(), StandardCharsets.UTF_8));
        response.disconnect();

        server.stop();

        return new ObjectMapper().readValue(body, ObjectNode.class);
    }

    public static ErrorResponse assertFlowFailsAtAuthorizationEndpoint(Function<URI, Profile> profileBuilder) throws IOException {
        RedirectionCaptureServer redirect = new RedirectionCaptureServer(true, "code");

        Profile profile = profileBuilder.apply(redirect.getRedirectUri());
        MockOAuth2Server server = new MockOAuth2Server(profile);
        server.start();

        redirect.start();
        Desktop.getDesktop()
                .browse(profile.buildEndpointParamsForAuthorization(server.getAuthorizationUri()));
        redirect.waitForRequestAndStop();
        assertTrue(redirect.wasCaptureAsExpected());

        server.stop();

        assertNull(redirect.getResponseParam("code"));
        assertNotNull(redirect.getResponseParam("error"), redirect.getResponseParam("error_message"));

        return new ErrorResponse(
                redirect.getResponseParam("error"),
                redirect.getResponseParam("error_message"),
                redirect.getResponseParam("state"));
    }

    public static ErrorResponse assertFlowFailsAtTokenEndpoint(Function<URI, Profile> profileBuilder) throws IOException {
        RedirectionCaptureServer redirect = new RedirectionCaptureServer(false, "code");

        Profile profile = profileBuilder.apply(redirect.getRedirectUri());
        MockOAuth2Server server = new MockOAuth2Server(profile);
        server.start();

        redirect.start();
        Desktop.getDesktop()
                .browse(profile.buildEndpointParamsForAuthorization(server.getAuthorizationUri()));
        redirect.waitForRequestAndStop();
        assertTrue(redirect.wasCaptureAsExpected());

        String code = redirect.getResponseParam("code");
        assertNotNull(code);
        assertNull(redirect.getResponseParam("error"), redirect.getResponseParam("error_message"));

        HttpResponseException ex = assertThrows(HttpResponseException.class, () ->
                new NetHttpTransport().createRequestFactory().buildPostRequest(
                                new GenericUrl(server.getTokenUri()),
                                ByteArrayContent.fromString("application/x-www-form-urlencoded",
                                        profile.buildEndpointParamsForToken(code)))
                        .execute()
        );

        server.stop();

        assertNull(new ObjectMapper().readValue(ex.getContent(), ObjectNode.class).get("access_token"));

        return new ObjectMapper().readValue(ex.getContent(), ErrorResponse.class);
    }
}
