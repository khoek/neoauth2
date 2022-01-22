package io.hoek.neoauth2;

import io.hoek.neoauth2.internal.JsonParamWriter;
import io.hoek.neoauth2.internal.ParamWriter;
import io.hoek.neoauth2.internal.Util;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;

public abstract class OAuthReponse extends WebApplicationException {

    private final ParamWriter.Writable content;

    OAuthReponse(ParamWriter.Writable content, Response response) {
        super(response);

        this.content = content;
    }

    public ParamWriter.Writable getContent() {
        return content;
    }

    public static final class Redirect extends OAuthReponse {

        private static Response buildResponse(ParamWriter<URI> writer, ParamWriter.Writable content) {
            return Util.addSecurityCacheControlHeaders(Response.status(Response.Status.FOUND))
                    .header("Location", writer.buildWith(content))
                    .build();
        }

        public Redirect(ParamWriter<URI> writer, ParamWriter.Writable content) {
            super(content, buildResponse(writer, content));
        }
    }

    public static final class JsonPage extends OAuthReponse {

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
