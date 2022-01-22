package io.hoek.neoauth2.backend;

import java.util.List;
import java.util.Map;

public interface UserRegistration {

    String getSub();

    default List<String> getGroups() {
        return List.of();
    }

    default Map<String, String> getCustomClaims() {
        return Map.of();
    }
}
