package io.hoek.neoauth2.backend.builtin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.hoek.neoauth2.backend.AuthorizationCodeIssuer;
import io.hoek.neoauth2.backend.AuthorizationCodeOrder;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.model.AuthorizationCodePayload;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Objects;

public class RandomAuthorizationCodeIssuer implements AuthorizationCodeIssuer {
    public static final int NUM_BYTES = 32;

    private final SecureRandom random = new SecureRandom();
    private final ObjectMapper mapper = new ObjectMapper();
    private final DataStore dataStore;

    public RandomAuthorizationCodeIssuer(DataStore dataStore) {
        this.dataStore = Objects.requireNonNull(dataStore);
    }

    @Override
    public AuthorizationCodePayload issueAuthorizationCode(AuthorizationCodeOrder content, Instant expiry) {
        String code = Util.generateRandomBytesBase64UrlEncodedWithoutPadding(random, NUM_BYTES);

        try {
            dataStore.put(code, new DataStore.Entry(mapper.writeValueAsString(content), expiry));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        return new AuthorizationCodePayload(code);
    }

    @Override
    public AuthorizationCodeOrder readAndVerifyAuthorizationCode(AuthorizationCodePayload payload) {
        DataStore.Entry entry = dataStore.get(payload.getCode());
        if (entry == null) {
            return null;
        }

        if (!entry.getAccessCount().isFirst()) {
            // TODO: Ideally we should revoke the token issued with the first use of the supplied code, since the spec
            //       says we should assume a compromise in this situation. Perhaps add a facility to report such
            //       violations.
            return null;
        }

        try {
            return mapper.readValue(entry.getValue(), AuthorizationCodeOrder.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
