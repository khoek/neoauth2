package io.hoek.neoauth2.exception;

import io.hoek.neoauth2.ParamWriter;
import io.hoek.neoauth2.internal.JsonParamWriter;
import io.hoek.neoauth2.internal.UriBuilderQueryParamWriter;
import io.hoek.neoauth2.internal.Util;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;

public abstract class WritableWebApplicationException extends WebApplicationException {

    private final ParamWriter.Writable content;

    WritableWebApplicationException(ParamWriter.Writable content, Response response) {
        super(response);

        this.content = content;
    }

    public ParamWriter.Writable getContent() {
        return content;
    }

    public static final class Redirect extends WritableWebApplicationException {

        private static Response buildResponse(URI baseUri, ParamWriter.Writable content) {
            URI uriLocation = new UriBuilderQueryParamWriter(baseUri).buildWith(content);
            return Util.addSecurityCacheControlHeaders(Response.status(Response.Status.FOUND))
                    .header("Location", uriLocation)
                    .build();
        }

        public Redirect(URI baseUri, ParamWriter.Writable content) {
            super(content, buildResponse(baseUri, content));
        }
    }

    public static final class JsonPage extends WritableWebApplicationException {

        private static Response buildResponse(Response.Status status, ParamWriter.Writable content) {
            String body = new JsonParamWriter().buildWith(content);
            return Util.addSecurityCacheControlHeaders(Response.status(status))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .entity(body)
                    .build();
        }

        public JsonPage(Response.Status status, ParamWriter.Writable content) {
            super(content, buildResponse(status, content));
        }
    }
}
