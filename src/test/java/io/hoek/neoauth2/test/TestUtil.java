package io.hoek.neoauth2.test;

import com.google.common.collect.Streams;
import org.apache.http.NameValuePair;
import org.junit.jupiter.params.provider.Arguments;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class TestUtil {

    public static Stream<List<?>> prependArguments(Stream<Arguments> prefix, Stream<List<?>> suffix) {
        return flatListPrefixProductStream(prefix.map(prefixElem -> List.of(prefixElem.get())), suffix);
    }

    public static Stream<List<?>> flatPrefixProductStream(Stream<?> prefix, Stream<List<?>> suffix) {
        return flatListPrefixProductStream(prefix.map(Arrays::asList), suffix);
    }

    public static Stream<List<?>> flatListPrefixProductStream(Stream<List<?>> prefix, Stream<List<?>> suffix) {
        List<List<?>> prefixList = prefix.collect(Collectors.toUnmodifiableList());
        return suffix.flatMap(suffixElem -> prefixList.stream().map(prefixElem ->
                Streams.concat(
                        prefixElem.stream(),
                        suffixElem.stream()).collect(Collectors.toList())));
    }

    public static String getSingleParam(List<NameValuePair> params, String name) {
        Set<String> values = params.stream()
                .filter(nv -> nv.getName().equalsIgnoreCase(name))
                .map(NameValuePair::getValue)
                .collect(Collectors.toUnmodifiableSet());

        if (values.size() == 0) {
            return null;
        }

        if (values.size() != 1) {
            throw new RuntimeException("multiple values for param: " + name);
        }

        return values.iterator().next();
    }

    public static String getRandom32Bytes() {
        return io.hoek.neoauth2.internal.Util.generateRandomBytesBase64UrlEncodedWithoutPadding(new SecureRandom(), 32);
    }
}
