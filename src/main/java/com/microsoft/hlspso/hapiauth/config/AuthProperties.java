package com.microsoft.hlspso.hapiauth.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the multi-issuer auth extension.
 *
 * <pre>
 * hapi:
 *   auth:
 *     enabled: true
 *     issuers:
 *       - id: entra-contoso
 *         issuerUri: https://login.microsoftonline.com/{tenantId}/v2.0
 *         audiences: [api://hapi-fhir]
 *         flavor: entra
 *       - id: smart-customerA
 *         issuerUri: https://auth.customerA.example/fhir
 *         jwksUri: https://auth.customerA.example/fhir/.well-known/jwks.json
 *         audiences: [https://hapi-fhir.example/fhir]
 *         flavor: smart
 *         tenant: customerA
 * </pre>
 */
@ConfigurationProperties(prefix = "hapi.auth")
public class AuthProperties {

    /** Master switch — when false the extension is a no-op. */
    private boolean enabled = false;

    /** When true, /fhir/metadata and Swagger UI are reachable anonymously. */
    private boolean allowAnonymousMetadata = true;

    /**
     * When true, requests that did NOT arrive via a reverse proxy
     * (i.e. carry no {@code X-Forwarded-For} header) bypass authentication.
     * This lets in-cluster callers (Mirth, synthea-loader, drc-tester, etc.)
     * keep talking to HAPI on the internal docker network while external
     * traffic through Traefik / Cloudflare still requires a Bearer token.
     */
    private boolean trustInternalNetwork = true;

    private final List<IssuerConfig> issuers = new ArrayList<>();

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public boolean isAllowAnonymousMetadata() { return allowAnonymousMetadata; }
    public void setAllowAnonymousMetadata(boolean allowAnonymousMetadata) {
        this.allowAnonymousMetadata = allowAnonymousMetadata;
    }

    public boolean isTrustInternalNetwork() { return trustInternalNetwork; }
    public void setTrustInternalNetwork(boolean trustInternalNetwork) {
        this.trustInternalNetwork = trustInternalNetwork;
    }

    public List<IssuerConfig> getIssuers() { return issuers; }

    public enum Flavor {
        /** Microsoft Entra (Azure AD) — scp/roles claim, azp/appid for client. */
        ENTRA,
        /** SMART on FHIR backend services — scope claim, sub/iss for client. */
        SMART
    }

    public static class IssuerConfig {
        private String id;
        private String issuerUri;
        /** Optional explicit JWKS URI — falls back to OIDC discovery from issuerUri. */
        private String jwksUri;
        private List<String> audiences = new ArrayList<>();
        private Flavor flavor = Flavor.SMART;
        /** Optional tenant/partition for multi-tenancy. */
        private String tenant;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getIssuerUri() { return issuerUri; }
        public void setIssuerUri(String issuerUri) { this.issuerUri = issuerUri; }
        public String getJwksUri() { return jwksUri; }
        public void setJwksUri(String jwksUri) { this.jwksUri = jwksUri; }
        public List<String> getAudiences() { return audiences; }
        public void setAudiences(List<String> audiences) { this.audiences = audiences; }
        public Flavor getFlavor() { return flavor; }
        public void setFlavor(Flavor flavor) { this.flavor = flavor; }
        public String getTenant() { return tenant; }
        public void setTenant(String tenant) { this.tenant = tenant; }
    }
}
