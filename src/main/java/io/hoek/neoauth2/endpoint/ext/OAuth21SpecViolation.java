package io.hoek.neoauth2.endpoint.ext;

import io.hoek.neoauth2.endpoint.AuthorizationRequestParser;

public abstract class OAuth21SpecViolation {

    private OAuth21SpecViolation() {
    }

    public static AllowImplicit allowImplicit() {
        return new AllowImplicit(true);
    }

    public static AllowImplicit allowImplicit(boolean requireNonce) {
        return new AllowImplicit(requireNonce);
    }

    public static DontRequirePkce dontRequirePkce() {
        return new DontRequirePkce();
    }

    // Allow the 'implicit' flow.
    public static final class AllowImplicit extends AuthorizationRequestParser.Extension {
        // Required by OIDC spec.
        private final boolean requireNonce;

        private AllowImplicit(boolean requireNonce) {
            this.requireNonce = requireNonce;
        }

        public boolean shouldRequireNonce() {
            return requireNonce;
        }
    }

    // Disable PKCE.
    public static final class DontRequirePkce extends AuthorizationRequestParser.Extension {
        private DontRequirePkce() {
        }
    }
}
