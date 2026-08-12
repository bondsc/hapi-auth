package com.microsoft.hlspso.hapiauth.jwt;

import java.util.List;
import java.util.Set;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/** Rejects a JWT whose {@code aud} contains none of the configured audiences. */
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private final Set<String> expected;

    public AudienceValidator(List<String> expected) {
        this.expected = Set.copyOf(expected);
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<String> aud = jwt.getAudience();
        if (aud != null) {
            for (String a : aud) {
                if (expected.contains(a)) return OAuth2TokenValidatorResult.success();
            }
        }
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                "invalid_token",
                "Required audience not present. Expected one of " + expected + " got " + aud,
                null));
    }
}
