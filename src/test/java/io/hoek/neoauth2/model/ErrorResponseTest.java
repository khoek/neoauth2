package io.hoek.neoauth2.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ErrorResponseTest {

    private String toJson(ErrorResponse response) {
        return assertDoesNotThrow(() -> new ObjectMapper().writeValueAsString(response));
    }

    private ErrorResponse fromJson(String json) {
        return assertDoesNotThrow(() -> new ObjectMapper().readValue(json, ErrorResponse.class));
    }

    private void assertPairIsConjugate(ErrorResponse er, String json) {
        assertEquals(er, fromJson(json));
        assertEquals(er, fromJson(toJson(er)));

        assertEquals(json, toJson(er));
        assertEquals(json, toJson(fromJson(json)));
    }

    @Test
    public void testBasic() {
        assertPairIsConjugate(
                new ErrorResponse(ErrorResponse.DESC_INVALID_REQUEST, "some error", "DEADBEEF"),
                "{\"error\":\"invalid_request\",\"error_message\":\"some error\",\"state\":\"DEADBEEF\"}");
    }

    @Test
    public void testNullFieldsDisappear() {
        assertPairIsConjugate(
                new ErrorResponse(ErrorResponse.DESC_INVALID_REQUEST, null, null),
                "{\"error\":\"invalid_request\"}");

        assertPairIsConjugate(
                new ErrorResponse(ErrorResponse.DESC_INVALID_REQUEST, "some error", null),
                "{\"error\":\"invalid_request\",\"error_message\":\"some error\"}");
    }
}
