package com.microsoft.hlspso.hapiauth.jwt;

import com.microsoft.hlspso.hapiauth.config.AuthProperties;
import com.microsoft.hlspso.hapiauth.config.AuthProperties.Flavor;
import com.microsoft.hlspso.hapiauth.config.AuthProperties.IssuerConfig;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Normalizes a validated JWT into a Spring {@link JwtAuthenticationToken} whose
 * principal is an {@link AuthenticatedPrincipal}. Handles both Entra and SMART
 * claim shapes per the multi-issuer requirements.
 */
public class PrincipalAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final Map<String, IssuerConfig> issuerIndex = new LinkedHashMap<>();

    public PrincipalAuthenticationConverter(AuthProperties props) {
        for (IssuerConfig ic : props.getIssuers()) {
            issuerIndex.put(ic.getIssuerUri(), ic);
        }
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        String issuer = jwt.getIssuer() != null ? jwt.getIssuer().toString() : null;
        IssuerConfig ic = issuerIndex.get(issuer);
        Flavor flavor = ic != null ? ic.getFlavor() : Flavor.SMART;
        String tenant = ic != null ? ic.getTenant() : null;

        Set<String> scopes = extractScopes(jwt, flavor);
        String clientId = extractClientId(jwt, flavor);

        AuthenticatedPrincipal principal = new AuthenticatedPrincipal(issuer, clientId, scopes, tenant);
        Collection<GrantedAuthority> authorities = scopes.stream()
                .map(s -> new SimpleGrantedAuthority("SCOPE_" + s))
                .collect(Collectors.toSet());

        JwtAuthenticationToken token = new JwtAuthenticationToken(jwt, authorities, clientId);
        token.setDetails(principal);
        return token;
    }

    private static Set<String> extractScopes(Jwt jwt, Flavor flavor) {
        Set<String> out = new HashSet<>();
        if (flavor == Flavor.ENTRA) {
            String scp = jwt.getClaimAsString("scp");
            if (scp != null) addSplit(out, scp);
            List<String> roles = safeStringList(jwt.getClaim("roles"));
            for (String r : roles) {
                out.add(mapEntraRoleToScope(r));
            }
        } else {
            String scope = jwt.getClaimAsString("scope");
            if (scope != null) addSplit(out, scope);
            // Some SMART issuers use scp too — accept it as fallback.
            String scp = jwt.getClaimAsString("scp");
            if (scp != null) addSplit(out, scp);
        }
        return out;
    }

    /**
     * Translate Entra app-role values (which cannot contain {@code /}) into
     * SMART-style {@code system/<resource>.<op>} scopes:
     * <ul>
     *   <li>{@code system.all} → {@code system/*.*}</li>
     *   <li>{@code system.read} / {@code system.write} → {@code system/*.read} / {@code system/*.write}</li>
     *   <li>{@code <Resource>.read} / {@code <Resource>.write} → {@code system/<Resource>.<op>}</li>
     *   <li>Anything already containing {@code /} is passed through unchanged.</li>
     * </ul>
     */
    static String mapEntraRoleToScope(String role) {
        if (role == null || role.isBlank()) return role;
        if (role.contains("/")) return role; // already SMART-shaped
        int dot = role.indexOf('.');
        if (dot < 0) return role;
        String left = role.substring(0, dot);
        String right = role.substring(dot + 1);
        if ("system".equalsIgnoreCase(left)) {
            if ("all".equalsIgnoreCase(right)) return "system/*.*";
            return "system/*." + right;
        }
        return "system/" + left + "." + right;
    }

    private static String extractClientId(Jwt jwt, Flavor flavor) {
        if (flavor == Flavor.ENTRA) {
            String azp = jwt.getClaimAsString("azp");
            if (azp != null && !azp.isBlank()) return azp;
            String appid = jwt.getClaimAsString("appid");
            if (appid != null && !appid.isBlank()) return appid;
        } else {
            String sub = jwt.getSubject();
            if (sub != null && !sub.isBlank()) return sub;
            if (jwt.getIssuer() != null) return jwt.getIssuer().toString();
        }
        return jwt.getSubject();
    }

    private static void addSplit(Set<String> out, String value) {
        for (String s : value.split("[\\s,]+")) {
            if (!s.isBlank()) out.add(s.trim());
        }
    }

    @SuppressWarnings("unchecked")
    private static List<String> safeStringList(Object raw) {
        if (raw instanceof List<?> l) {
            return l.stream().filter(o -> o instanceof String).map(o -> (String) o).toList();
        }
        return List.of();
    }
}
