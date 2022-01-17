package io.hoek.neoauth2.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PkceInfo {
    private CodeChallengeMethod method;
    private String challenge;
}
