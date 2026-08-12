package com.microsoft.hlspso.hapiauth.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Permit-all filter chain used when the JWT auth extension is DISABLED
 * ({@code hapi.auth.enabled} is absent or not {@code true}).
 *
 * <p>The extension bundles the spring-security jars into WEB-INF/lib so the
 * enabled path ({@link SecurityConfig}) has them available. As a side effect,
 * spring-security is always on the classpath, which makes Spring Boot's
 * {@code SecurityAutoConfiguration} install a default chain that locks down
 * every endpoint (HTTP 401 with a generated password). That is wrong for the
 * default unauthenticated dev/interop container.
 *
 * <p>Providing this explicit permit-all {@link SecurityFilterChain} suppresses
 * Spring Boot's default chain (which backs off on any user-defined
 * SecurityFilterChain bean) and keeps {@code /fhir/**} open when auth is off.
 */
@Configuration
@ConditionalOnProperty(prefix = "hapi.auth", name = "enabled", havingValue = "false", matchIfMissing = true)
public class NoAuthSecurityConfig {

    @Bean
    SecurityFilterChain hapiNoAuthFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(reg -> reg.anyRequest().permitAll());
        return http.build();
    }
}
