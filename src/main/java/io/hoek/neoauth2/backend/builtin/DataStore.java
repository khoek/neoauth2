package io.hoek.neoauth2.backend.builtin;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.With;

import java.time.Instant;

public interface DataStore<T> {
    /**
     * Returns an {@code Entry} previously assigned to {@code key} or {@code null} if no such value exists/the value has
     * expired. The returned {@code Entry}'s access count is updated and is {@code AccessCount.SUBSEQUENT} upon all
     * further invocations (in total {@code AccessCount.FIRST} is returned exactly once across all threads). If this
     * operation caused the {@code Entry} of the assigned {@code key} to be detected as expired this method instead
     * removes the {@code key} and returns {@code null}.
     * <p>
     * This method is safe to call concurrently.
     *
     * @param key the key to look up in the store
     * @return an {@code Entry} representing the value assigned to {@code key}
     */
    default Entry get(String key) {
        Entry e = getUncheckedExpiry(key);
        if (e == null) {
            return null;
        }

        if (e.getExpiry().isBefore(Instant.now())) {
            remove(key);
            return null;
        }

        return e;
    }

    /**
     * Returns an {@code Entry} previously assigned to {@code key} or {@code null} if no such value exists/the value has
     * expired. The returned {@code Entry}'s access count is updated and is {@code AccessCount.SUBSEQUENT} upon all
     * further invocations (in total {@code AccessCount.FIRST} is returned exactly once across all threads). If this
     * operation caused the {@code Entry} of the assigned {@code key} to be detected as expired no action must be taken.
     * <p>
     * This method is safe to call concurrently.
     *
     * @param key the key to look up in the store
     * @return a {@code Hit} representing the value assigned to {@code key}
     */
    Entry getUncheckedExpiry(String key);

    /**
     * @param key   the key to use
     * @param value the value to assign to the {@code key}, but {@code value} may be deleted earlier if
     *              {@code value.getExpiry()} is more than {@code DataStore.MAX_EXPIRES_IN_SECS} seconds in the future
     */
    void put(String key, Entry value);

    /**
     * @param key the key to remove
     */
    void remove(String key);

    @Getter
    @AllArgsConstructor
    class Entry {
        private final String value;
        private final Instant expiry;
        @With
        private final AccessCount accessCount;

        public Entry(String value, Instant expiry) {
            this(value, expiry, AccessCount.FIRST);
        }

        enum AccessCount {
            FIRST,
            SUBSEQUENT,
            ;

            public boolean isFirst() {
                return this == AccessCount.FIRST;
            }
        }
    }

}
