package io.hoek.neoauth2.extension;

import io.hoek.neoauth2.AuthorizationRequestParser;

public abstract class OAuth21SpecOption {

    private OAuth21SpecOption() {
    }

    public static AllowPlainCodeChallengeMethod allowPlainCodeChallengeMethod() {
        return new AllowPlainCodeChallengeMethod();
    }

    // Enable the 'plain' code challenge method.
    public static final class AllowPlainCodeChallengeMethod extends AuthorizationRequestParser.Extension {
        private AllowPlainCodeChallengeMethod() {
        }
    }
}
