package io.hoek.neoauth2.internal;

import io.hoek.neoauth2.endpoint.ReturnErrorResponseException;
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

    public ReturnErrorResponseException toRedirectException(URI redirectUri, String state) {
        return new ReturnErrorResponseException.Redirect(redirectUri, new ErrorResponse(error, errorMessage, state));
    }

    public ReturnErrorResponseException toErrorPageException() {
        return toErrorPageException(null);
    }

    public ReturnErrorResponseException toErrorPageException(String state) {
        return new ReturnErrorResponseException.ErrorPage(new ErrorResponse(error, errorMessage, state));
    }

    public ReturnErrorResponseException toErrorPageException(Response.Status status, String state) {
        return new ReturnErrorResponseException.ErrorPage(status, new ErrorResponse(error, errorMessage, state));
    }
}
