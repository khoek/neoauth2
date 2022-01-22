package io.hoek.neoauth2.backend.builtin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.hoek.util.function.Throw;
import io.hoek.neoauth2.backend.AuthorizationAuthority;
import io.hoek.neoauth2.backend.UserAuthorization;
import io.hoek.neoauth2.internal.Util;
import io.hoek.neoauth2.model.AuthorizationCodePayload;

import javax.validation.constraints.NotNull;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Objects;

public class RandomCodeAuthorizationAuthority implements AuthorizationAuthority {
    public static final int NUM_BYTES = 32;

    private final SecureRandom random = new SecureRandom();
    private final ObjectMapper mapper = new ObjectMapper();
    private final DataStore dataStore;

    public RandomCodeAuthorizationAuthority(@NotNull DataStore dataStore) {
        this.dataStore = Objects.requireNonNull(dataStore);
    }

    @Override
    public AuthorizationCodePayload issueAuthorizationCode(UserAuthorization content, Instant expiry) {
        String code = Util.generateRandomBytesBase64UrlEncodedWithoutPadding(random, NUM_BYTES);

        Throw.asRuntime(() -> dataStore.put(code, new DataStore.Entry(mapper.writeValueAsString(content), expiry)));

        return new AuthorizationCodePayload(code);
    }

    @Override
    public UserAuthorization readAndVerifyAuthorizationCode(AuthorizationCodePayload payload) {
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

        return Throw.asRuntime(() -> mapper.readValue(entry.getValue(), UserAuthorization.class));
    }
}
