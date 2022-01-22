package io.hoek.neoauth2;

import io.hoek.neoauth2.backend.ClientRegistration;
import io.hoek.util.function.Catch;
import io.hoek.neoauth2.backend.IssuerBundle;
import io.hoek.neoauth2.internal.InvalidRequestException;
import io.hoek.neoauth2.model.ErrorResponse;
import lombok.Data;
import lombok.NonNull;

import javax.ws.rs.core.Response;

@Data
public class TokenRequestGranter {

    private final @NonNull IssuerBundle bundle;
    private final @NonNull ClientRegistration client;
    private final @NonNull TokenRequest request;

    public final OAuthReponse.JsonPage deny() {
        return deny("server denied access");
    }

    public final OAuthReponse.JsonPage deny(String reason) {
        return new OAuthReponse.JsonPage(
                Response.Status.BAD_REQUEST,
                new ErrorResponse(ErrorResponse.DESC_ACCESS_DENIED, reason, null));
    }

    public final OAuthReponse.JsonPage grant() {
        return new OAuthReponse.JsonPage(
                Response.Status.OK,
                Catch.insteadOf(InvalidRequestException.class,
                        () -> request.generateAccessGrantedWritable(bundle, client),
                        InvalidRequestException::getErrorResponse));
    }
}
