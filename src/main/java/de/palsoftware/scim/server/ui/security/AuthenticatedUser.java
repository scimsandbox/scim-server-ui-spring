package de.palsoftware.scim.server.ui.security;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Locale;
import java.util.Map;

public final class AuthenticatedUser {

    private AuthenticatedUser() {
    }

    public static String email(Authentication authentication) {
        if (authentication == null) {
            throw new InvalidAuthenticatedPrincipalException("Missing authentication");
        }
        String resolved = resolveEmail(authentication);
        if (resolved != null) {
            return resolved;
        }
        if (authentication.getPrincipal() instanceof OidcUser) {
            throw new InvalidAuthenticatedPrincipalException("Authenticated principal is missing a verified email address");
        }
        throw new InvalidAuthenticatedPrincipalException("Unable to resolve authenticated email");
    }

    public static String resolveEmail(Authentication authentication) {
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return null;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof OidcUser oidcUser) {
            return resolveEmail(oidcUser);
        }
        String fallback = authentication.getName();
        return (fallback == null || fallback.isBlank()) ? null : fallback;
    }

    public static String displayName(Authentication authentication) {
        if (authentication == null) {
            return null;
        }
        return email(authentication);
    }

    public static boolean isAdmin(Authentication authentication) {
        if (authentication == null) {
            return false;
        }
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if ("ROLE_ADMIN".equals(authority.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    public static boolean isEmailVerified(OidcUser oidcUser) {
        if (oidcUser == null) {
            return false;
        }
        Boolean directVerified = oidcUser.getEmailVerified();
        if (directVerified != null) {
            return directVerified;
        }
        Map<String, Object> claims = oidcUser.getClaims();
        if (claims != null) {
            Object rawVerified = claims.get("email_verified");
            if (rawVerified instanceof Boolean verified) {
                return verified;
            }
            if (rawVerified instanceof String verifiedStr) {
                return "true".equalsIgnoreCase(verifiedStr.trim());
            }
        }
        return false;
    }

    public static String resolveEmail(OidcUser oidcUser) {
        if (!isEmailVerified(oidcUser)) {
            return null;
        }
        return normalizeEmail(oidcUser.getEmail());
    }

    public static String normalizeEmail(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (normalized.isEmpty() || !normalized.contains("@")) {
            return null;
        }
        return normalized;
    }
}
