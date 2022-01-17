package io.hoek.neoauth2.test;

import io.hoek.neoauth2.ParamReader;
import lombok.Data;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
public class Param {
    private final String key;
    private final String value;

    public static final class MockReader extends ParamReader {

        private final Collection<Param> params;

        public MockReader(Collection<Param> params) {
            this.params = params;
        }

        @Override
        public List<String> get(String name) {
            return params.stream()
                    .filter(param -> param.getKey().equals(name))
                    .map(Param::getValue)
                    .collect(Collectors.toUnmodifiableList());
        }
    }
}