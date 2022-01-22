package io.hoek.neoauth2.internal;

public class WithStateWriter implements ParamWriter.Writable {
    private final String state;
    private final ParamWriter.Writable writable;

    public WithStateWriter(String state, ParamWriter.Writable writable) {
        this.state = state;
        this.writable = writable;
    }

    @Override
    public void writeTo(ParamWriter<?> writer) {
        if(state != null) {
            writer.set("state", state);
        }

        writable.writeTo(writer);
    }
}
