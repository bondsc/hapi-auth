package com.microsoft.hlspso.hapiauth.interceptor;

import ca.uhn.fhir.rest.api.RestOperationTypeEnum;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.exceptions.ForbiddenOperationException;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import com.microsoft.hlspso.hapiauth.config.AuthProperties;
import com.microsoft.hlspso.hapiauth.jwt.AuthenticatedPrincipal;
import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * HAPI interceptor that builds an authorization rule list per request based on
 * SMART {@code system/<resource>.<op>} scopes carried on the authenticated
 * principal. Read-class operations (read/vread/search/history/capabilities) map
 * to {@code .read}; mutating operations map to {@code .write}.
 */
public class ScopeAuthorizationInterceptor extends AuthorizationInterceptor {

    private final AuthProperties props;

    public ScopeAuthorizationInterceptor(AuthProperties props) {
        this.props = props;
    }

    @Override
    public List<IAuthRule> buildRuleList(RequestDetails requestDetails) {
        // Internal-network bypass: requests that did not arrive via a reverse
        // proxy (no X-Forwarded-For) are trusted when configured. Matches the
        // SecurityConfig rule so the docker network keeps working with auth on.
        if (props.isTrustInternalNetwork()
                && requestDetails.getHeader("X-Forwarded-For") == null) {
            return new RuleBuilder().allowAll("internal-network").build();
        }

        AuthenticatedPrincipal principal = currentPrincipal();

        // Always allow capability discovery — Spring Security may already permit it.
        RestOperationTypeEnum op = requestDetails.getRestOperationType();
        if (op == RestOperationTypeEnum.METADATA) {
            return new RuleBuilder().allowAll("metadata").build();
        }

        if (principal == null) {
            throw new AuthenticationException("Unauthenticated request");
        }

        boolean isRead = isReadOperation(op);
        boolean isWrite = isWriteOperation(op);
        String resourceType = requestDetails.getResourceName(); // may be null for system-level

        // Wildcard fast-path — also covers _include / _revinclude resources.
        if (isRead && principal.hasSystemWildcard("read")) {
            return new RuleBuilder().allowAll("system-read").build();
        }
        if (isWrite && principal.hasSystemWildcard("write")) {
            return new RuleBuilder().allowAll("system-write").build();
        }

        // System-level (no specific resource) and no wildcard → deny.
        if (resourceType == null) {
            throw new ForbiddenOperationException(
                    "Token lacks system/*.read or system/*.write for operation " + op);
        }

        if (isRead && principal.hasSystemScope(resourceType, "read")) {
            // Allow read for the primary resource AND every other resource type
            // the token grants read on, so _include / _revinclude work.
            RuleBuilder rb = new RuleBuilder();
            rb.allow("read-" + resourceType).read().resourcesOfType(resourceType).withAnyId().andThen();
            for (String extra : principal.systemReadableResourceTypes("read")) {
                if (extra.equalsIgnoreCase(resourceType)) continue;
                rb.allow("read-" + extra).read().resourcesOfType(extra).withAnyId().andThen();
            }
            return rb.build();
        }
        if (isWrite && principal.hasSystemScope(resourceType, "write")) {
            RuleBuilder rb = new RuleBuilder();
            rb.allow("write-" + resourceType).write().resourcesOfType(resourceType).withAnyId().andThen();
            rb.allow("read-" + resourceType).read().resourcesOfType(resourceType).withAnyId().andThen();
            for (String extra : principal.systemReadableResourceTypes("read")) {
                if (extra.equalsIgnoreCase(resourceType)) continue;
                rb.allow("read-" + extra).read().resourcesOfType(extra).withAnyId().andThen();
            }
            return rb.build();
        }

        throw new ForbiddenOperationException(
                "Token lacks required system/" + resourceType
                        + "." + (isWrite ? "write" : "read") + " scope");
    }

    private static AuthenticatedPrincipal currentPrincipal() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a == null || !a.isAuthenticated()) return null;
        if (a instanceof JwtAuthenticationToken jat && jat.getDetails() instanceof AuthenticatedPrincipal ap) {
            return ap;
        }
        return null;
    }

    private static boolean isReadOperation(RestOperationTypeEnum op) {
        if (op == null) return false;
        return switch (op) {
            case READ, VREAD, SEARCH_TYPE, SEARCH_SYSTEM, HISTORY_INSTANCE,
                 HISTORY_TYPE, HISTORY_SYSTEM, GET_PAGE, METADATA -> true;
            default -> false;
        };
    }

    private static boolean isWriteOperation(RestOperationTypeEnum op) {
        if (op == null) return false;
        return switch (op) {
            case CREATE, UPDATE, PATCH, DELETE, TRANSACTION, BATCH -> true;
            default -> false;
        };
    }
}
