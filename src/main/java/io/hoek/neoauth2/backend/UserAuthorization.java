package io.hoek.neoauth2.backend;

import io.hoek.neoauth2.model.PkceInfo;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.net.URI;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class UserAuthorization {
    // FIXME FIXME How to make final?

    private TokenSpec spec;

    private boolean redirectUriProvided;
    private URI redirectUri;

    private PkceInfo pkceInfo;
}
