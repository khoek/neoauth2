package io.hoek.neoauth2.test.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.api.client.http.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.common.collect.Streams;
import com.google.common.io.CharStreams;
import io.hoek.neoauth2.AuthorizationRequestParser;
import io.hoek.neoauth2.model.ErrorResponse;
import io.hoek.neoauth2.test.Param;
import io.hoek.neoauth2.test.TestUtil;
import lombok.Data;
import lombok.Getter;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.apache.http.NameValuePair;

import javax.ws.rs.core.UriBuilder;
import java.awt.*;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

public class Flows {

    private Flows() {
    }

    private static URI buildGetUrlParamsUri(URI requestUri, Collection<Param> params) {
        UriBuilder builder = UriBuilder.fromUri(requestUri);
        params.forEach(param -> builder.queryParam(param.getKey(), param.getValue()));
        return builder.build();
    }

    private static String buildPostBodyParams(Collection<Param> params) {
        return params.stream()
                .map(param -> URLEncoder.encode(param.getKey(), StandardCharsets.UTF_8) + '=' + URLEncoder.encode(param.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }

    private static <Flow extends AuthorizationFlowPhase> AuthorizationStepResult<Flow> performAuthorizationStep(List<AuthorizationRequestParser.Extension> extensions, Function<URI, Flow> flowBuilder, boolean expectError, String errorIfHeaderMissing) throws IOException {
        RedirectionCaptureServer redirect = new RedirectionCaptureServer(expectError, errorIfHeaderMissing);

        Flow flow = flowBuilder.apply(redirect.getRedirectUri());

        MockOAuth2Server server = new MockOAuth2Server(flow, extensions);
        server.start();

        Collection<Param> params = flow.getAuthorizationEndpointParams();
        if (params == null) {
            // Skip the authorization step
            return new AuthorizationStepResult<>(server, flow, null);
        }

        redirect.start();
        Desktop.getDesktop().browse(buildGetUrlParamsUri(server.getAuthorizationUri(), params));
        redirect.waitForRequestAndStop();
        assertTrue(redirect.wasCaptureAsExpected());

        return new AuthorizationStepResult<>(server, flow, redirect.getResponseParams());
    }

    public static ErrorResponse assertAuthorizationCodeFlowFailsAtAuthorizationEndpoint(Function<URI, ? extends AuthorizationCode<Void>> flowBuilder) throws IOException {
        return assertAuthorizationCodeFlowFailsAtAuthorizationEndpoint(List.of(), flowBuilder);
    }

    public static ErrorResponse assertAuthorizationCodeFlowFailsAtAuthorizationEndpoint(List<AuthorizationRequestParser.Extension> extensions, Function<URI, ? extends AuthorizationCode<Void>> flowBuilder) throws IOException {
        AuthorizationStepResult<? extends AuthorizationCode<Void>> result = performAuthorizationStep(extensions, flowBuilder, true, "code");

        result.getServer().stop();

        assertNotNull(result.getRedirectUriParams());
        assertNull(result.getRedirectUriParam("code"));
        assertNotNull(result.getRedirectUriParam("error"), result.getRedirectUriParam("error_message"));

        return new ErrorResponse(result.getRedirectUriParam("error"), result.getRedirectUriParam("error_message"), result.getRedirectUriParam("state"));
    }

    public static ObjectNode assertImplicitFlowSucceeds(Function<URI, ? extends Implicit> flowBuilder) throws IOException {
        return assertImplicitFlowSucceeds(List.of(), flowBuilder);
    }

    public static ObjectNode assertImplicitFlowSucceeds(List<AuthorizationRequestParser.Extension> extensions, Function<URI, ? extends Implicit> flowBuilder) throws IOException {
        AuthorizationStepResult<? extends Implicit> result = performAuthorizationStep(extensions, flowBuilder, false, "access_token");
        result.getServer().stop();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        root.set("access_token", mapper.convertValue(result.assertRedirectUriParamPresent("access_token"), JsonNode.class));
        root.set("token_type", mapper.convertValue(result.assertRedirectUriParamPresent("token_type"), JsonNode.class));
        root.set("expires_in", mapper.convertValue(result.assertRedirectUriParamPresent("expires_in"), JsonNode.class));
        root.set("scope", mapper.convertValue(result.assertRedirectUriParamPresent("scope"), JsonNode.class));
        if (result.getRedirectUriParam("state") != null) {
            root.set("state", mapper.convertValue(result.getRedirectUriParam("state"), JsonNode.class));
        }
        return root;
    }

    public static ErrorResponse assertImplicitFlowFails(Function<URI, ? extends Implicit> flowBuilder) throws IOException {
        return assertImplicitFlowFails(List.of(), flowBuilder);
    }

    public static ErrorResponse assertImplicitFlowFails(List<AuthorizationRequestParser.Extension> extensions, Function<URI, ? extends Implicit> flowBuilder) throws IOException {
        AuthorizationStepResult<? extends Implicit> result = performAuthorizationStep(extensions, flowBuilder, true, "access_token");
        result.getServer().stop();

        return new ErrorResponse(result.assertRedirectUriParamPresent("error"), result.getRedirectUriParam("error_message"), result.getRedirectUriParam("state"));
    }

    public static <R> R assertAuthorizationCodeFlowCompletes(List<AuthorizationRequestParser.Extension> extensions, Function<URI, ? extends AuthorizationCode<R>> flowBuilder) throws IOException {
        AuthorizationStepResult<? extends AuthorizationCode<R>> result = performAuthorizationStep(extensions, flowBuilder, false, "code");

        String code = null;

        // If `getRedirectUriParams()` returns `null` then we skipped the authorization step, so just press on with a
        // `null` code.
        if (result.getRedirectUriParams() != null) {
            code = result.getRedirectUriParam("code");
            assertNotNull(code);
            assertNull(result.getRedirectUriParam("error"), result.getRedirectUriParam("error_message"));
        }

        R ret = result.getFlow().completeFlow(new TokenEndpoint(result.getServer().getTokenUri()), code);

        result.getServer().stop();

        return ret;
    }

    public static ObjectNode assertAuthorizationCodeFlowSucceeds(Function<URI, ? extends AuthorizationCode<TokenEndpointResponse>> flowBuilder) throws IOException {
        return assertAuthorizationCodeFlowSucceeds(List.of(), flowBuilder);
    }

    public static ObjectNode assertAuthorizationCodeFlowSucceeds(List<AuthorizationRequestParser.Extension> extensions, Function<URI, ? extends AuthorizationCode<TokenEndpointResponse>> flowBuilder) throws IOException {
        return assertAuthorizationCodeFlowCompletes(extensions, flowBuilder).unwrapSuccess();
    }

    public static void assertIsTokenEndpointErrorResponse(TokenEndpointResponse response) {
        assertTrue(response.isError());
        assertNull(response.getResponse().get("access_token"));
        assertTrue(Set.of("error", "error_message", "state")
                .containsAll(Streams.stream(response.getResponse().fieldNames())
                        .collect(Collectors.toUnmodifiableSet())));
    }

    public static ErrorResponse assertAuthorizationCodeFlowFailsAtTokenEndpoint(Function<URI, ? extends AuthorizationCode<TokenEndpointResponse>> flowBuilder) throws IOException {
        return assertAuthorizationCodeFlowFailsAtTokenEndpoint(List.of(), flowBuilder);
    }

    public static ErrorResponse assertAuthorizationCodeFlowFailsAtTokenEndpoint(List<AuthorizationRequestParser.Extension> extensions, Function<URI, ? extends AuthorizationCode<TokenEndpointResponse>> flowBuilder) throws IOException {
        return assertAuthorizationCodeFlowFailsAtTokenEndpoint(400, extensions, flowBuilder);
    }

    public static ErrorResponse assertAuthorizationCodeFlowFailsAtTokenEndpoint(int errorCode, List<AuthorizationRequestParser.Extension> extensions, Function<URI, ? extends AuthorizationCode<TokenEndpointResponse>> flowBuilder) throws IOException {
        TokenEndpointResponse er = assertAuthorizationCodeFlowCompletes(extensions, flowBuilder);
        assertEquals(errorCode, er.getHttpCode());
        assertIsTokenEndpointErrorResponse(er);
        return new ObjectMapper().convertValue(er.getResponse(), ErrorResponse.class);
    }

    public interface AuthorizationFlowPhase extends MockOAuth2Server.Configuration {

        Collection<Param> getAuthorizationEndpointParams();

        default String getExpectedAuthorizationResponseState() {
            return null;
        }
    }

    public static abstract class AuthorizationCode<T> implements AuthorizationFlowPhase {

        // Returning null means to skip this step and pass `null` to the `code` argument of `doTokenStep()`.
        public abstract Collection<Param> getAuthorizationEndpointParams();

        public abstract T completeFlow(Flows.TokenEndpoint endpoint, String code);
    }

    public static abstract class Implicit implements AuthorizationFlowPhase {

        public abstract @NonNull Collection<Param> getAuthorizationEndpointParams();
    }

    @Data
    public static class TokenEndpointResponse {

        private final int httpCode;
        private final ObjectNode response;

        public boolean isError() {
            return httpCode != 200;
        }

        public ObjectNode unwrapSuccess() {
            assertFalse(isError());
            return response;
        }
    }

    public static class TokenEndpoint {

        private final URI endpointUri;

        public TokenEndpoint(URI endpointUri) {
            this.endpointUri = endpointUri;
        }

        @SneakyThrows(IOException.class)
        public TokenEndpointResponse performRequest(Collection<Param> params) {
            HttpRequest request = new NetHttpTransport().createRequestFactory()
                    .buildPostRequest(new GenericUrl(endpointUri), ByteArrayContent.fromString("application/x-www-form-urlencoded", buildPostBodyParams(params)));

            int httpCode;
            String body;
            try {
                HttpResponse response = request.execute();
                httpCode = response.getStatusCode();
                body = CharStreams.toString(new InputStreamReader(response.getContent(), StandardCharsets.UTF_8));
                response.disconnect();
            } catch (HttpResponseException ex) {
                httpCode = ex.getStatusCode();
                body = ex.getContent();
            }

            return new TokenEndpointResponse(httpCode, new ObjectMapper().readValue(body, ObjectNode.class));
        }
    }

    @Getter
    private static class AuthorizationStepResult<Flow extends AuthorizationFlowPhase> {

        private final MockOAuth2Server server;

        private final Flow flow;
        private final List<NameValuePair> redirectUriParams;

        public AuthorizationStepResult(MockOAuth2Server server, Flow flow, List<NameValuePair> redirectUriParams) {
            this.server = server;
            this.flow = flow;
            this.redirectUriParams = redirectUriParams;

            assertEquals(this.flow.getExpectedAuthorizationResponseState(), getRedirectUriParam("state"));
        }

        public String getRedirectUriParam(String name) {
            return TestUtil.getSingleParam(redirectUriParams, name);
        }

        public String assertRedirectUriParamPresent(String name) {
            String value = getRedirectUriParam(name);
            assertNotNull(value);
            return value;
        }
    }
}
