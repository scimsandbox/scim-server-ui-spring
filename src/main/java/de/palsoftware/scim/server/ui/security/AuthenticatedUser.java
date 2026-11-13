package de.palsoftware.scim.server.ui.security;

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
            throw new IllegalStateException("Missing authentication");
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof OidcUser oidcUser) {
            String resolved = resolveEmail(oidcUser);
            if (resolved != null) {
                return resolved;
            }
            throw new IllegalStateException("Authenticated principal is missing a verified email address");
        }
        String fallback = authentication.getName();
        if (fallback == null || fallback.isBlank()) {
            throw new IllegalStateException("Unable to resolve authenticated email");
        }
        return fallback;
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
        if (Boolean.TRUE.equals(oidcUser.getEmailVerified())) {
            return true;
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
