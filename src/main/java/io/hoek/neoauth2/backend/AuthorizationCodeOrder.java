package io.hoek.neoauth2.backend;

import io.hoek.neoauth2.model.CodeChallengeMethod;
import io.hoek.neoauth2.model.PkceInfo;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.net.URI;
import java.util.List;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class AuthorizationCodeOrder {
    // FIXME FIXME How to make final?

    private String sub;

    private String clientId;
    private List<String> scopes;

    private boolean redirectUriProvided;
    private URI redirectUri;

    private PkceInfo pkceInfo;

    // SPEC NOTE: Nonstandard OIDC extension
    private String nonce;
}
