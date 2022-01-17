package io.hoek.neoauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.SneakyThrows;

import javax.ws.rs.core.UriBuilder;
import java.net.URI;

public abstract class ParamWriter<Result> {

    public interface Writable {
        void writeTo(ParamWriter<?> writer);
    }

    public abstract void set(String param, String value);

    public abstract void set(String param, long value);

    public abstract Result build();

    public final Result buildWith(ParamWriter.Writable writable) {
        writable.writeTo(this);
        return build();
    }
}
