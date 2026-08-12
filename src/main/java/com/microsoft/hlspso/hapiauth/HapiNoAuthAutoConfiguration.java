package com.microsoft.hlspso.hapiauth;

import com.microsoft.hlspso.hapiauth.security.NoAuthSecurityConfig;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * Always-on auto-configuration that wires the permit-all security chain when
 * the JWT auth extension is disabled. Kept separate from
 * {@link HapiAuthAutoConfiguration} (which is gated on
 * {@code hapi.auth.enabled=true}) so exactly one of the two chains is active.
 *
 * @see NoAuthSecurityConfig
 */
@Configuration
@Import(NoAuthSecurityConfig.class)
public class HapiNoAuthAutoConfiguration {
}
