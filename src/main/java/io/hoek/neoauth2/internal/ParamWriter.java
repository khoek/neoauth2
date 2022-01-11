package io.hoek.neoauth2.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.SneakyThrows;

import javax.ws.rs.core.UriBuilder;
import java.net.URI;

public interface ParamWriter {

    static URI writeToUri(URI uri, ParamWriter.Writable writable) {
        return writeToUriWithState(uri, null, writable);
    }

    static URI writeToUriWithState(URI uri, String state, ParamWriter.Writable writable) {
        UriBuilderQueryParamWriter writer = new UriBuilderQueryParamWriter(uri);
        writable.writeTo(writer);
        if (state != null) {
            writer.set("state", state);
        }
        return writer.build();
    }

    static String writeToJson(ParamWriter.Writable writable) {
        JsonParamWriter writer = new JsonParamWriter();
        writable.writeTo(writer);
        return writer.build();
    }

    void set(String param, String value);

    void set(String param, long value);

    interface Writable {
        void writeTo(ParamWriter writer);
    }

    final class UriBuilderQueryParamWriter implements ParamWriter {
        private final UriBuilder builder;

        public UriBuilderQueryParamWriter(URI uri) {
            this.builder = UriBuilder.fromUri(uri);
        }

        @Override
        public void set(String param, String value) {
            builder.replaceQueryParam(param, value);
        }

        @Override
        public void set(String param, long value) {
            builder.replaceQueryParam(param, value);
        }

        public URI build() {
            return builder.build();
        }
    }

    final class JsonParamWriter implements ParamWriter {
        private final ObjectMapper mapper = new ObjectMapper();
        private final ObjectNode root = mapper.createObjectNode();

        public JsonParamWriter() {
        }

        @Override
        public void set(String param, String value) {
            root.put(param, value);
        }

        @Override
        public void set(String param, long value) {
            root.put(param, value);
        }

        @SneakyThrows
        public String build() {
            return mapper.writeValueAsString(root);
        }
    }
}
