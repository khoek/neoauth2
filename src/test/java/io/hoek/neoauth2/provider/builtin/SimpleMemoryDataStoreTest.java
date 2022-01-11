package io.hoek.neoauth2.provider.builtin;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class SimpleMemoryDataStoreTest {

    @Test
    public void test() {
        DataStore ds = new SimpleMemoryDataStore();

        assertNull(ds.get("BLAH"));

        assertNull(ds.get("A"));
        ds.put("A", new DataStore.Entry("B1", Instant.now().plus(Duration.ofHours(5000))));

        {
            DataStore.Entry e = ds.get("A");
            assertEquals("B1", e.getValue());
            assertEquals(DataStore.Entry.AccessCount.FIRST, e.getAccessCount());
        }

        assertNull(ds.get("B"));

        {
            DataStore.Entry e = ds.get("A");
            assertEquals("B1", e.getValue());
            assertEquals(DataStore.Entry.AccessCount.SUBSEQUENT, e.getAccessCount());
        }

        {
            DataStore.Entry e = ds.get("A");
            assertEquals(e.getValue(), "B1");
            assertEquals(DataStore.Entry.AccessCount.SUBSEQUENT, e.getAccessCount());
        }

        ds.put("A", new DataStore.Entry("B2", Instant.now().plus(Duration.ofHours(5000))));

        {
            DataStore.Entry e = ds.get("A");
            assertEquals("B2", e.getValue());
            assertEquals(e.getAccessCount(), DataStore.Entry.AccessCount.FIRST);
        }

        {
            DataStore.Entry e = ds.get("A");
            assertEquals("B2", e.getValue());
            assertEquals(DataStore.Entry.AccessCount.SUBSEQUENT, e.getAccessCount());
        }

        ds.remove("A");
        assertNull(ds.get("A"));

        ds.put("X", new DataStore.Entry("B3", Instant.now().plus(Duration.ofHours(5000))));

        assertNull(ds.get("A"));
        ds.put("A", new DataStore.Entry("B1", Instant.now().plus(Duration.ofHours(5000))));

        {
            DataStore.Entry e = ds.get("A");
            assertEquals("B1", e.getValue());
            assertEquals(DataStore.Entry.AccessCount.FIRST, e.getAccessCount());
        }
    }
}
