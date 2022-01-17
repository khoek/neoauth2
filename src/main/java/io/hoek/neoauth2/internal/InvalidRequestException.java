package io.hoek.neoauth2.internal;

import io.hoek.neoauth2.exception.WritableWebApplicationException.Redirect;
import io.hoek.neoauth2.exception.WritableWebApplicationException.JsonPage;
import io.hoek.neoauth2.model.ErrorResponse;

import javax.ws.rs.core.Response;
import java.net.URI;

public class InvalidRequestException extends Exception {

    private final String error;
    private final String errorMessage;

    public InvalidRequestException(String error, String errorMessage) {
        this.error = error;
        this.errorMessage = errorMessage;
    }

    public String getError() {
        return error;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public Redirect toRedirectException(URI redirectUri, String state) {
        return new Redirect(redirectUri, new ErrorResponse(error, errorMessage, state));
    }

    public JsonPage toErrorPageException() {
        return toErrorPageException(null);
    }

    // FIXME Consider properly supporting the 401 which is supposed to be returned in that specific instance as per the
    //       OAuth spec (Ctrl-F to find it)
    public JsonPage toErrorPageException(String state) {
        return new JsonPage(Response.Status.BAD_REQUEST, new ErrorResponse(error, errorMessage, state));
    }

    public JsonPage toErrorPageException(Response.Status status, String state) {
        return new JsonPage(status, new ErrorResponse(error, errorMessage, state));
    }
}
