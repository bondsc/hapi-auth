package com.microsoft.hlspso.hapiauth.jwt;

import com.microsoft.hlspso.hapiauth.config.AuthProperties;
import com.microsoft.hlspso.hapiauth.config.AuthProperties.IssuerConfig;
import com.nimbusds.jwt.JWTParser;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Dispatches incoming JWTs to a per-issuer {@link NimbusJwtDecoder} chosen from
 * the configured issuer table. Each decoder validates signature (via cached
 * JWKS), issuer, audience, and expiration.
 */
public class MultiIssuerJwtDecoder implements JwtDecoder {

    private final Map<String, JwtDecoder> decoders = new LinkedHashMap<>();
    private final Map<String, JwtDecoder> built = new ConcurrentHashMap<>();
    private final Map<String, IssuerConfig> configs;

    public MultiIssuerJwtDecoder(AuthProperties props) {
        this.configs = new LinkedHashMap<>();
        for (IssuerConfig ic : props.getIssuers()) {
            if (ic.getIssuerUri() == null || ic.getIssuerUri().isBlank()) continue;
            configs.put(ic.getIssuerUri(), ic);
            // Pre-build eagerly so misconfiguration fails at startup.
            decoders.put(ic.getIssuerUri(), buildDecoder(ic));
        }
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        String issuer = peekIssuer(token);
        if (issuer == null) {
            throw new BadJwtException("JWT is missing iss claim");
        }
        JwtDecoder decoder = decoders.get(issuer);
        if (decoder == null) {
            // Lazy build in case configs were updated; otherwise reject.
            IssuerConfig ic = configs.get(issuer);
            if (ic == null) {
                throw new JwtValidationException("Unknown token issuer: " + issuer,
                        java.util.List.of(new OAuth2Error("invalid_token",
                                "Issuer " + issuer + " is not registered", null)));
            }
            decoder = built.computeIfAbsent(issuer, k -> buildDecoder(ic));
        }
        return decoder.decode(token);
    }

    private static String peekIssuer(String token) {
        try {
            Object iss = JWTParser.parse(token).getJWTClaimsSet().getIssuer();
            return iss != null ? iss.toString() : null;
        } catch (ParseException e) {
            throw new BadJwtException("Malformed JWT", e);
        }
    }

    private static JwtDecoder buildDecoder(IssuerConfig ic) {
        NimbusJwtDecoder decoder;
        if (ic.getJwksUri() != null && !ic.getJwksUri().isBlank()) {
            decoder = NimbusJwtDecoder.withJwkSetUri(ic.getJwksUri()).build();
        } else {
            // OIDC discovery from issuer URI — caches JWKS internally.
            decoder = (NimbusJwtDecoder) org.springframework.security.oauth2.jwt.JwtDecoders
                    .fromIssuerLocation(ic.getIssuerUri());
        }

        var validators = new java.util.ArrayList<org.springframework.security.oauth2.core.OAuth2TokenValidator<Jwt>>();
        validators.add(JwtValidators.createDefaultWithIssuer(ic.getIssuerUri()));
        if (ic.getAudiences() != null && !ic.getAudiences().isEmpty()) {
            validators.add(new AudienceValidator(ic.getAudiences()));
        }
        decoder.setJwtValidator(new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(validators));
        return decoder;
    }
}
