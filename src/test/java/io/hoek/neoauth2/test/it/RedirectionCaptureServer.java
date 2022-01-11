package io.hoek.neoauth2.test.it;

import com.sun.net.httpserver.HttpServer;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import java.io.OutputStreamWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.stream.Collectors;

public class RedirectionCaptureServer extends SimpleEphemeralServer {

    public static final String ENDPOINT_PATH = "/redirect_endpoint";

    private final String errorIfHeaderMissing;
    private final boolean expectError;

    private boolean wasCaptureAsExpected = false;
    private final Semaphore sem = new Semaphore(0);
    private List<NameValuePair> params = null;

    public RedirectionCaptureServer(boolean expectError, String errorIfHeaderMissing) {
        super();

        this.expectError = expectError;
        this.errorIfHeaderMissing = errorIfHeaderMissing;
    }

    public URI getRedirectUri() {
        return getEndpointUri(ENDPOINT_PATH);
    }

    public void waitForRequestAndStop() {
        sem.acquireUninterruptibly();
        stop();
    }

    public String getResponseParam(String param) {
        Set<String> values = params.stream()
                .filter(nv -> nv.getName().equalsIgnoreCase(param))
                .map(NameValuePair::getValue)
                .collect(Collectors.toUnmodifiableSet());

        if (values.size() == 0) {
            return null;
        }

        if (values.size() != 1) {
            throw new RuntimeException("multiple values for param: " + param);
        }

        return values.iterator().next();
    }

    private String buildAutoClosingPage(String body) {
        return "<html><head><script>setTimeout(function() {window.close()}, 10);</script></head><body>" + body + "</body></html>\n";
    }

    private String buildStandardPage(String body) {
        return "<html><body>" + body + "</body></html>\n";
    }

    public boolean wasCaptureAsExpected() {
        return wasCaptureAsExpected;
    }

    @Override
    protected void setup(HttpServer server) {
        server.createContext(ENDPOINT_PATH, exchange -> {
            params = URLEncodedUtils.parse(exchange.getRequestURI(), StandardCharsets.UTF_8);
            sem.release();

            exchange.sendResponseHeaders(200, 0);
            OutputStreamWriter doc = new OutputStreamWriter(exchange.getResponseBody(), StandardCharsets.UTF_8);
            if (getResponseParam("error") != null
                    || (errorIfHeaderMissing != null && getResponseParam(errorIfHeaderMissing) == null)) {
                if(expectError) {
                    doc.write(buildAutoClosingPage("Expected error occurred (yay)"));
                    wasCaptureAsExpected = true;
                } else {
                    doc.write(buildStandardPage("Unexpected error! (fail)"));
                }
            } else {
                if(expectError) {
                    doc.write(buildStandardPage("Unexpected success! (fail)"));
                } else {
                    doc.write(buildAutoClosingPage("Success (yay)"));
                    wasCaptureAsExpected = true;
                }
            }
            doc.close();
        });
    }

}
