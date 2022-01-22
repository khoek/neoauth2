package io.hoek.neoauth2.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.hoek.neoauth2.internal.ParamWriter;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotNull;

// FIXME how can we have JSON working with the `final`s

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ErrorResponse implements ParamWriter.Writable {

    public static final String DESC_INVALID_REQUEST = "invalid_request";
    public static final String DESC_INVALID_GRANT = "invalid_grant";
    public static final String DESC_INVALID_CLIENT = "invalid_client";
    public static final String DESC_UNAUTHORIZED_CLIENT = "unauthorized_client";
    public static final String DESC_ACCESS_DENIED = "access_denied";
    public static final String DESC_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    public static final String DESC_UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    public static final String DESC_INVALID_SCOPE = "invalid_scope";
    public static final String DESC_SERVER_ERROR = "server_error";
    public static final String DESC_TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";

    @NotNull
    public String error;

    public String errorMessage;

    public String state;

    @Override
    public void writeTo(ParamWriter<?> writer) {
        writer.set("error", error);

        if (errorMessage != null) {
            writer.set("error_message", errorMessage);
        }

        if (state != null) {
            writer.set("state", state);
        }
    }

    public String toString() {
        return error + " (" + errorMessage + ") " + (state != null ? " [" + state + "]" : "");
    }
}
