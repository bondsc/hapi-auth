package com.microsoft.hlspso.hapiauth;

import ca.uhn.fhir.rest.server.RestfulServer;
import com.microsoft.hlspso.hapiauth.config.AuthProperties;
import com.microsoft.hlspso.hapiauth.interceptor.ScopeAuthorizationInterceptor;
import com.microsoft.hlspso.hapiauth.security.SecurityConfig;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * Auto-configuration entry point. Activates only when
 * {@code hapi.auth.enabled=true} so the extension stays a no-op for the
 * default unauthenticated dev container.
 */
@Configuration
@EnableConfigurationProperties(AuthProperties.class)
@ConditionalOnProperty(prefix = "hapi.auth", name = "enabled", havingValue = "true")
@Import(SecurityConfig.class)
public class HapiAuthAutoConfiguration {

    private final ObjectProvider<RestfulServer> restfulServer;
    private final AuthProperties authProperties;

    public HapiAuthAutoConfiguration(ObjectProvider<RestfulServer> restfulServer,
                                     AuthProperties authProperties) {
        this.restfulServer = restfulServer;
        this.authProperties = authProperties;
    }

    @Bean
    ScopeAuthorizationInterceptor scopeAuthorizationInterceptor(AuthProperties props) {
        return new ScopeAuthorizationInterceptor(props);
    }

    @PostConstruct
    void registerInterceptor() {
        RestfulServer server = restfulServer.getIfAvailable();
        if (server != null) {
            server.registerInterceptor(scopeAuthorizationInterceptor(authProperties));
        }
    }
}
