package io.hoek.neoauth2;

import io.hoek.neoauth2.backend.ClientRegistration;
import io.hoek.neoauth2.backend.UserRegistration;
import io.hoek.util.function.Catch;
import io.hoek.neoauth2.backend.IssuerBundle;
import io.hoek.neoauth2.internal.InvalidRequestException;
import io.hoek.neoauth2.internal.WithStateWriter;
import io.hoek.neoauth2.model.ErrorResponse;
import lombok.Data;
import lombok.NonNull;

import java.util.Objects;

@Data
public class AuthorizationRequestGranter {

    private final @NonNull ClientRegistration client;
    private final @NonNull AuthorizationRequest request;

    public final OAuthReponse.Redirect deny() {
        return deny("resource owner denied access");
    }

    public final OAuthReponse.Redirect deny(String reason) {
        return new OAuthReponse.Redirect(
                request.getResponseType().getWriter(request.getRedirectUri()),
                new ErrorResponse(ErrorResponse.DESC_ACCESS_DENIED, reason, request.state));
    }

    public final OAuthReponse.Redirect grant(IssuerBundle bundle, UserRegistration user) {
        Objects.requireNonNull(bundle);
        Objects.requireNonNull(user);

        return new OAuthReponse.Redirect(
                request.getResponseType().getWriter(request.getRedirectUri()),
                new WithStateWriter(request.state, Catch.insteadOf(InvalidRequestException.class,
                        () -> request.generateAccessGrantedWritable(bundle, client, user),
                        InvalidRequestException::getErrorResponse
                )));
    }
}
