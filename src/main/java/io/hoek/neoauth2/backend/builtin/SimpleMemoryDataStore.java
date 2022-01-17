package io.hoek.neoauth2.backend.builtin;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class SimpleMemoryDataStore implements DataStore {
    private final Cache<String, Entry> entries = CacheBuilder.newBuilder()
            .expireAfterWrite(MAX_EXPIRES_IN_SECS, TimeUnit.SECONDS)
            .build();

    public SimpleMemoryDataStore() {
        this(false);
    }

    public SimpleMemoryDataStore(boolean silent) {
        if (!silent) {
            Logger.getLogger(SimpleMemoryDataStore.class.getName())
                    .warning("This datastore cannot be shared by multiple authorization server instances --- do not use in production!");
        }
    }

    @Override
    public Entry getUncheckedExpiry(String key) {
        Entry e = entries.getIfPresent(key);
        if (e == null) {
            return null;
        }

        entries.put(key, e.withAccessCount(Entry.AccessCount.SUBSEQUENT));
        return e;
    }

    @Override
    public void put(String key, Entry value) {
        entries.put(key, value);
    }

    @Override
    public void remove(String key) {
        entries.invalidate(key);
    }
}