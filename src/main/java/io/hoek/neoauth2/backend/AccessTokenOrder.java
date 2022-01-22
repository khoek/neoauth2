package io.hoek.neoauth2.backend;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class AccessTokenOrder {

    private TokenSpec spec;

    private final long expiresInSecs;
}
