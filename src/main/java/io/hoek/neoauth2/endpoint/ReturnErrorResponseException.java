package io.hoek.neoauth2.endpoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.hoek.neoauth2.internal.ParamWriter;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.model.ErrorResponse;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;

// Thrown when a standard OAuth error response should be returned.
public abstract class ReturnErrorResponseException extends Exception {

    private final ErrorResponse errorResponse;

    public ReturnErrorResponseException(ErrorResponse errorResponse) {
        super(errorResponse.getError() + " (" + errorResponse.getErrorMessage() + ") [" + errorResponse.getState() + "]");
        this.errorResponse = errorResponse;
    }

    public ErrorResponse getOAuthErrorResponse() {
        return errorResponse;
    }

    public abstract Response toResponse();

    public static class Redirect extends ReturnErrorResponseException {

        private final URI redirectUri;

        public Redirect(URI redirectUri, ErrorResponse errorResponse) {
            super(errorResponse);

            this.redirectUri = redirectUri;
        }

        public URI getRedirectUri() {
            return redirectUri;
        }

        @Override
        public Response toResponse() {
            URI uriLocation = ParamWriter.writeToUri(getRedirectUri(), getOAuthErrorResponse());
            return Util.addSecurityCacheControlHeaders(Response.status(Response.Status.FOUND))
                    .header("Location", uriLocation)
                    .build();
        }
    }

    // FIXME consider properly supporting the 401 which is supposed to be returned in that specific instance
    public static class ErrorPage extends ReturnErrorResponseException {
        private static final ObjectMapper MAPPER = new ObjectMapper();

        private final Response.Status status;

        public ErrorPage(ErrorResponse errorResponse) {
            this(Response.Status.BAD_REQUEST, errorResponse);
        }

        public ErrorPage(Response.Status status, ErrorResponse errorResponse) {
            super(errorResponse);
            this.status = status;
        }

        public Response.Status getStatus() {
            return status;
        }

        @Override
        public Response toResponse() {
            String body = ParamWriter.writeToJson(getOAuthErrorResponse());
            return Util.addSecurityCacheControlHeaders(Response.status(getStatus()))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .entity(body)
                    .build();
        }
    }

}
