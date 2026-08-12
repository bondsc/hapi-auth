package com.microsoft.hlspso.hapiauth.jwt;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Normalized representation of a validated M2M token, independent of issuer flavor.
 * Stored as the principal on the Spring {@code Authentication} so HAPI interceptors
 * can read it without caring whether the source was Entra or SMART.
 */
public final class AuthenticatedPrincipal {

    private final String issuer;
    private final String clientId;
    private final Set<String> scopes;
    private final String tenant;

    public AuthenticatedPrincipal(String issuer, String clientId, Set<String> scopes, String tenant) {
        this.issuer = issuer;
        this.clientId = clientId;
        this.scopes = Set.copyOf(scopes);
        this.tenant = tenant;
    }

    public String getIssuer() { return issuer; }
    public String getClientId() { return clientId; }
    public Set<String> getScopes() { return scopes; }
    public String getTenant() { return tenant; }

    public boolean hasScope(String scope) { return scopes.contains(scope); }

    /** True if any granted scope satisfies {@code system/<resource>.<op>} or wildcards. */
    public boolean hasSystemScope(String resourceType, String operation) {
        for (String s : scopes) {
            if (!s.startsWith("system/")) continue;
            String body = s.substring("system/".length()); // e.g. *.read, Patient.write, *.*
            int dot = body.indexOf('.');
            if (dot < 0) continue;
            String resPart = body.substring(0, dot);
            String opPart = body.substring(dot + 1);
            boolean resOk = "*".equals(resPart) || resPart.equalsIgnoreCase(resourceType);
            boolean opOk = "*".equals(opPart) || opPart.equalsIgnoreCase(operation)
                    || ("write".equalsIgnoreCase(opPart) && ("write".equalsIgnoreCase(operation) || "*".equals(operation)));
            if (resOk && opOk) return true;
        }
        return false;
    }

    /** True if the principal carries a {@code system/*.<op>} (or {@code system/*.*}) wildcard. */
    public boolean hasSystemWildcard(String operation) {
        return hasSystemScope("*", operation);
    }

    /**
     * Explicit (non-wildcard) resource types granted for the given op via
     * {@code system/<Resource>.<op>} or {@code system/<Resource>.*} scopes.
     * Callers should first check {@link #hasSystemWildcard(String)} and treat
     * that as "all resources".
     */
    public Set<String> systemReadableResourceTypes(String operation) {
        Set<String> out = new LinkedHashSet<>();
        for (String s : scopes) {
            if (!s.startsWith("system/")) continue;
            String body = s.substring("system/".length());
            int dot = body.indexOf('.');
            if (dot < 0) continue;
            String resPart = body.substring(0, dot);
            String opPart = body.substring(dot + 1);
            if ("*".equals(resPart)) continue;
            boolean opOk = "*".equals(opPart) || opPart.equalsIgnoreCase(operation);
            if (opOk) out.add(resPart);
        }
        return out;
    }

    @Override
    public String toString() {
        return "AuthenticatedPrincipal{client=" + clientId + ", issuer=" + issuer
                + ", tenant=" + tenant + ", scopes=" + scopes + "}";
    }
}
