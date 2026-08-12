package com.microsoft.hlspso.hapiauth.security;

import com.microsoft.hlspso.hapiauth.config.AuthProperties;
import com.microsoft.hlspso.hapiauth.jwt.MultiIssuerJwtDecoder;
import com.microsoft.hlspso.hapiauth.jwt.PrincipalAuthenticationConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Spring Security filter chain that enforces Bearer JWT authentication on
 * /fhir/** when the extension is enabled. Anonymous access to /fhir/metadata
 * and Swagger UI is preserved by default so capability discovery still works.
 * Internal docker-network callers (those reaching HAPI directly, without
 * Traefik in front) bypass auth when {@code hapi.auth.trust-internal-network}
 * is true — see {@link AuthProperties#isTrustInternalNetwork()}.
 */
@Configuration
public class SecurityConfig {

    /**
     * Matches requests that did NOT arrive via a reverse proxy. Traefik
     * (and any normal RP) appends X-Forwarded-For; direct intra-container
     * HTTP calls don't, so this is a reliable internal/external splitter
     * for the docker network.
     */
    static final RequestMatcher INTERNAL_REQUEST =
            req -> req.getHeader("X-Forwarded-For") == null;

    @Bean
    JwtDecoder hapiAuthJwtDecoder(AuthProperties props) {
        return new MultiIssuerJwtDecoder(props);
    }

    @Bean
    PrincipalAuthenticationConverter hapiAuthConverter(AuthProperties props) {
        return new PrincipalAuthenticationConverter(props);
    }

    @Bean
    SecurityFilterChain hapiAuthFilterChain(HttpSecurity http,
                                            JwtDecoder decoder,
                                            PrincipalAuthenticationConverter converter,
                                            AuthProperties props) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(reg -> {
                if (props.isTrustInternalNetwork()) {
                    reg.requestMatchers(INTERNAL_REQUEST).permitAll();
                }
                if (props.isAllowAnonymousMetadata()) {
                    reg.requestMatchers(
                            "/fhir/metadata",
                            "/fhir/.well-known/**",
                            "/fhir/swagger-ui/**",
                            "/fhir/api-docs/**"
                    ).permitAll();
                }
                reg.requestMatchers("/actuator/health", "/actuator/info").permitAll();
                reg.requestMatchers("/fhir/**").authenticated();
                reg.anyRequest().permitAll();
            })
            .oauth2ResourceServer(oauth -> oauth
                .jwt(jwt -> jwt.decoder(decoder).jwtAuthenticationConverter(converter)));
        return http.build();
    }
}
