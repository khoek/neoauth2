package io.hoek.neoauth2.internal;

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
