package io.hoek.neoauth2.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.SneakyThrows;

public final class JsonParamWriter extends ParamWriter<String> {
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