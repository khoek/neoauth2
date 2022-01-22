package io.hoek.neoauth2.test.it;

import com.google.common.io.CharStreams;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.hoek.neoauth2.*;
import io.hoek.neoauth2.backend.ClientRegistration;
import io.hoek.neoauth2.backend.IssuerBundle;
import io.hoek.neoauth2.backend.UserRegistration;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class MockOAuth2Server extends SimpleEphemeralServer {

    public final String ENDPOINT_AUTHORIZATION = "/authorization";
    public final String ENDPOINT_TOKEN = "/token";

    private final Configuration config;
    private final List<AuthorizationRequestParser.Extension> extensions;

    public MockOAuth2Server(Configuration config, List<AuthorizationRequestParser.Extension> extensions) {
        super();

        this.config = config;
        this.extensions = extensions;
    }

    public static ParamReader readerFromNameValuePairs(List<NameValuePair> params) {
        return new ParamReader() {
            @Override
            public List<String> get(String param) {
                return params.stream()
                        .filter(nv -> nv.getName().equalsIgnoreCase(param))
                        .map(NameValuePair::getValue)
                        .collect(Collectors.toUnmodifiableList());
            }
        };
    }

    public static ParamReader readerFromUri(URI uri) {
        return readerFromNameValuePairs(URLEncodedUtils.parse(uri, StandardCharsets.UTF_8));
    }

    public static ParamReader readerFromQueryString(String query) {
        return readerFromNameValuePairs(URLEncodedUtils.parse(query, StandardCharsets.UTF_8));
    }

    private static void setResponse(HttpExchange exchange, Response response) {
        byte[] body;
        if (response.getEntity() != null) {
            // Brittle
            body = response.getEntity().toString().getBytes(StandardCharsets.UTF_8);
        } else {
            body = new byte[0];
        }

        for (Map.Entry<String, List<Object>> header : response.getHeaders().entrySet()) {
            exchange.getResponseHeaders().put(header.getKey(), header.getValue().stream()
                    .map(Object::toString) // Brittle
                    .collect(Collectors.toList()));
        }

        try {
            exchange.sendResponseHeaders(response.getStatus(), body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public URI getAuthorizationUri() {
        return getEndpointUri(ENDPOINT_AUTHORIZATION);
    }

    public URI getTokenUri() {
        return getEndpointUri(ENDPOINT_TOKEN);
    }

    @Override
    protected void setup(HttpServer server) {
        server.createContext(ENDPOINT_AUTHORIZATION, exchange -> {
            if (!exchange.getRequestMethod().equals("GET")) {
                throw new RuntimeException("not a GET request");
            }

            setResponse(exchange, doEndpointAuthorization(readerFromUri(exchange.getRequestURI())));
        });

        server.createContext(ENDPOINT_TOKEN, exchange -> {
            if (!exchange.getRequestMethod().equals("POST")) {
                throw new RuntimeException("not a POST request");
            }

            setResponse(exchange,
                    doEndpointToken(readerFromQueryString(CharStreams.toString(new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8)))));
        });
    }

    private Response doEndpointAuthorization(ParamReader params) {
        try {
            AuthorizationRequestParser parser = AuthorizationRequest.parser();
            extensions.forEach(parser::addExtension);

            return parser
                    .parse(config.getClientRegistration(), params)
                    .grant(config.getIssuerBundle(), config.getUserRegistration())
                    .getResponse();
        } catch (WebApplicationException e) {
            return e.getResponse();
        } catch (Exception e) {
            Logger.getLogger(MockOAuth2Server.class.getName()).severe(e.toString());
            e.printStackTrace();

            System.exit(1);
            throw new InternalError();
        }
    }

    public Response doEndpointToken(ParamReader params) {
        try {
            return TokenRequest.parser()
                    .parse(config.getIssuerBundle(), config.getClientRegistration(), params)
                    .grant()
                    .getResponse();
        } catch (WebApplicationException e) {
            return e.getResponse();
        } catch (Exception e) {
            Logger.getLogger(MockOAuth2Server.class.getName()).severe(e.toString());
            e.printStackTrace();

            System.exit(1);
            throw new InternalError();
        }
    }

    public interface Configuration {

        IssuerBundle getIssuerBundle();

        ClientRegistration getClientRegistration();

        UserRegistration getUserRegistration();
    }
}
