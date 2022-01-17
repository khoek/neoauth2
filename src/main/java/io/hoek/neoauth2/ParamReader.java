package io.hoek.neoauth2;

import io.hoek.neoauth2.internal.InvalidRequestException;
import io.hoek.neoauth2.model.ErrorResponse;

import java.util.Iterator;
import java.util.List;
import java.util.function.Function;

public abstract class ParamReader {

    public abstract List<String> get(String param);

    public final String maybeExtractSingletonParam(String param) throws InvalidRequestException {
        List<String> l = get(param);
        if (l == null) {
            return null;
        }

        Iterator<String> it = l.iterator();
        if (!it.hasNext()) {
            return null;
        }

        String s = it.next();
        if (it.hasNext()) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "duplicate param '" + param + "'");
        }

        return s;
    }

    public final String extractSingletonParam(String param) throws InvalidRequestException {
        String value = maybeExtractSingletonParam(param);
        if (value == null) {
            throw new InvalidRequestException(ErrorResponse.DESC_INVALID_REQUEST, "missing param '" + param + "'");
        }

        return value;
    }

    public static ParamReader from(Function<String, List<String>> getFn) {
        return new ParamReader() {
            @Override
            public List<String> get(String param) {
                return getFn.apply(param);
            }
        };
    }
}
