package io.hoek.neoauth2.internal;

import io.hoek.neoauth2.model.ErrorResponse;

public final class InvalidRequestException extends Exception {

    private final String error;
    private final String errorMessage;

    public InvalidRequestException(String error, String errorMessage) {
        this.error = error;
        this.errorMessage = errorMessage;
    }

    public ErrorResponse getErrorResponse() {
        return getErrorResponseWithState(null);
    }

    public ErrorResponse getErrorResponseWithState(String state) {
        return new ErrorResponse(error, errorMessage, state);
    }

    // FIXME Consider properly supporting the 401 which is supposed to be returned in that specific instance as per the
    //       OAuth spec (Ctrl-F to find it)
}
