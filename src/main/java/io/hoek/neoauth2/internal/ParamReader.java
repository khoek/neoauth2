package io.hoek.neoauth2.internal;

import java.util.List;

public interface ParamReader {

    List<String> get(String param);
}
